import os
from datetime import datetime
from flask import Blueprint, current_app, render_template, request, redirect, url_for, flash, send_from_directory, abort
from flask_login import login_required, current_user
from . import db
from .models import CA, Certificate, User
from .ca_utils import create_ca, issue_cert

bp = Blueprint('main', __name__)


@bp.route('/')
@login_required
def index():
    cas = CA.query.order_by(CA.created_at.desc()).all()
    certs_by_ca = {c.id: Certificate.query.filter_by(ca_id=c.id).order_by(Certificate.created_at.desc()).all() for c in cas}
    return render_template('index.html', cas=cas, certs_by_ca=certs_by_ca)

def admin_required(func):
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Permís denegat', 'danger')
            return redirect(url_for('main.index'))
        return func(*args, **kwargs)
    return wrapper

@bp.route('/ca/new', methods=['GET', 'POST'])
@login_required
@admin_required
def ca_new():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        tld = request.form.get('tld', '').strip()
        if not name or not tld:
            flash('Name and TLD are required', 'danger')
            return redirect(url_for('main.index'))

        # Prevent duplicates per TLD
        if CA.query.filter_by(tld=tld).first():
            flash('A CA for this TLD already exists', 'warning')
            return redirect(url_for('main.index'))

        cert_path, key_path = create_ca(current_app.config['CERTS_ROOT'], name, tld)
        ca = CA(name=name, tld=tld, cert_path=cert_path, key_path=key_path)
        db.session.add(ca)
        db.session.commit()
        flash(f'Created CA for .{tld}', 'success')
        return redirect(url_for('main.ca_detail', ca_id=ca.id))
    return render_template('ca_new.html')


@bp.route('/ca/<int:ca_id>')
def ca_detail(ca_id):
    ca = CA.query.get_or_404(ca_id)
    certs = Certificate.query.filter_by(ca_id=ca.id).order_by(Certificate.created_at.desc()).all()
    return render_template('ca_detail.html', ca=ca, certs=certs)


@bp.route('/ca/<int:ca_id>/download')
def ca_download(ca_id):
    ca = CA.query.get_or_404(ca_id)
    directory = os.path.dirname(ca.cert_path)
    filename = os.path.basename(ca.cert_path)
    return send_from_directory(directory=directory, path=filename, as_attachment=True)


@bp.route('/ca/<int:ca_id>/issue', methods=['POST'])
@login_required
def issue(ca_id):
    ca = CA.query.get_or_404(ca_id)
    common_name = request.form.get('common_name', '').strip()
    san_raw = request.form.get('san', '').strip()
    days_valid = int(request.form.get('days_valid', '825'))

    if not common_name:
        flash('Common Name is required', 'danger')
        return redirect(url_for('main.ca_detail', ca_id=ca.id))

    # Force CN to end with the CA TLD if not provided
    if not common_name.endswith(f'.{ca.tld}'):
        common_name = f"{common_name}.{ca.tld}"

    san_dns = [d.strip() for d in san_raw.split(',') if d.strip()]
    # Ensure SANs include CN (Browsers rely on SAN)
    if common_name not in san_dns:
        san_dns.append(common_name)

    cert_path, key_path, expires = issue_cert(
        current_app.config['CERTS_ROOT'], ca.cert_path, ca.key_path, ca.tld,
        common_name, san_dns, days_valid=days_valid,
        serial_int=ca.next_serial()
    )
    db.session.add(ca)  # serial increment persisted

    cert = Certificate(
        ca_id=ca.id,
        common_name=common_name,
        san=','.join(san_dns),
        expires_at=expires,
        cert_path=cert_path,
        key_path=key_path,
    )
    db.session.add(cert)
    db.session.commit()

    flash(f'Issued cert for {common_name}', 'success')
    return redirect(url_for('main.ca_detail', ca_id=ca.id))

@bp.route('/ca/<int:ca_id>/delete', methods=['GET'])
@login_required
@admin_required
def ca_delete(ca_id):
    ca = CA.query.get_or_404(ca_id)
    # Delete all issued certificates
    certs = Certificate.query.filter_by(ca_id=ca.id).all()
    for cert in certs:
        for p in [cert.cert_path, cert.key_path, os.path.splitext(cert.cert_path)[0] + '-bundle.pem']:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass
        db.session.delete(cert)
    # Remove CA files
    for p in [ca.cert_path, ca.key_path]:
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass
    db.session.delete(ca)
    db.session.commit()
    flash('CA and all issued certificates deleted', 'info')
    return redirect(url_for('main.index')) 


@bp.route('/cert/<int:cert_id>/download')
@login_required
def cert_download(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    kind = request.args.get('type', 'bundle')  # bundle|crt|key
    if kind == 'crt':
        filepath = cert.cert_path
    elif kind == 'key':
        filepath = cert.key_path
    elif kind == 'bundle':
        # Convert bundle path from cert path
        base = os.path.splitext(cert.cert_path)[0]
        filepath = base + '-bundle.pem'
    else:
        abort(400, 'Invalid type')

    return send_from_directory(directory=os.path.dirname(filepath), path=os.path.basename(filepath), as_attachment=True)


@bp.route('/cert/<int:cert_id>/delete', methods=['POST'])
@login_required
def cert_delete(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    # Remove files
    for p in [cert.cert_path, cert.key_path, os.path.splitext(cert.cert_path)[0] + '-bundle.pem']:
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass
    db.session.delete(cert)
    db.session.commit()
    flash('Certificate deleted', 'info')
    return redirect(url_for('main.ca_detail', ca_id=cert.ca_id))

@bp.route('/users', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_users():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'reader')
        if User.query.filter_by(username=username).first():
            flash('Ja existeix aquest usuari', 'warning')
        else:
            u = User(username=username, role=role)
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            flash('Usuari creat', 'success')
    users = User.query.all()
    return render_template('users.html', users=users)

@bp.route('/users/<int:user_id>/delete', methods=['GET'])
@login_required
@admin_required
def user_delete(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('No pots eliminar-te a tu mateix', 'danger')
        return redirect(url_for('main.manage_users'))
    db.session.delete(user)
    db.session.commit()
    flash('Usuari eliminat', 'info')
    return redirect(url_for('main.manage_users'))

