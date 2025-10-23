from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from .models import db, User

bp = Blueprint('auth', __name__)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('main.index'))
        flash('Usuari o contrasenya incorrectes', 'danger')
    return render_template('login.html')

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sessió tancada', 'info')
    return redirect(url_for('auth.login'))

@bp.route('/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if current_user.role != 'admin':
        flash('Permís denegat', 'danger')
        return redirect(url_for('main.index'))

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
def user_delete(user_id):
    if current_user.role != 'admin':
        flash('Permís denegat', 'danger')
        return redirect(url_for('main.index'))
    
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('No pots eliminar-te a tu mateix', 'danger')
        return redirect(url_for('main.manage_users'))
    db.session.delete(user)
    db.session.commit()
    flash('Usuari eliminat', 'info')
    return redirect(url_for('main.manage_users'))

