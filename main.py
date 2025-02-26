from flask import Flask, render_template, request, redirect, url_for, session  # flask轻量级的 Web 框架
from flask_sqlalchemy import SQLAlchemy  # flask_sqlalchemy操作数据库
from werkzeug.security import generate_password_hash, check_password_hash  # 生成和验证密码哈希
import random

app = Flask(__name__)  # 用于确定应用的位置，以便 Flask 能找到相关资源
app.secret_key = 'your_very_secret_key_here'  # 设置了应用的密钥，用于保证会话等安全相关功能的正常运行
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # 配置了应用的数据库连接信息，这里指定使用 SQLite 数据库，数据库文件名为 “users.db”
db = SQLAlchemy(app)  # 创建了一个 SQLAlchemy 对象，并将 Flask 应用实例传入，以便在应用中使用 SQLAlchemy 进行数据库操作。


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(10), unique=True, nullable=False)
    password = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(200))
    phone = db.Column(db.String(11))


with app.app_context():
    db.create_all()


def generate_captcha():
    captcha = str(random.randint(1000, 9999))
    return captcha


@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    # captcha = generate_captcha()
    # session['captcha'] = captcha

    if request.method == 'POST':
        # 先保存旧验证码用于比对
        old_captcha = session.get('captcha', '')  # 使用 session 对象的 get 方法来获取键为 'captcha' 的值，如果键不存在则返回空字符串

        # 处理登录逻辑
        # “filter_by” 是一种数据库查询方法，用于指定查询条件，这里指定了以 “username” 字段为条件进行筛选。“.first ()” 方法用于获取查询结果中的第一条记录。
        user = User.query.filter_by(username=request.form['username']).first()
        password_valid = user and check_password_hash(user.password, request.form['password'])
        captcha_valid = request.form['captcha'] == old_captcha

        # 无论验证结果如何都生成新验证码
        new_captcha = generate_captcha()
        session['captcha'] = new_captcha

        if not password_valid:
            error = ('Invalid credentials \n'
                     '无效的账号或密码')
        elif not captcha_valid:
            error = ('Invalid captcha \n'
                     '验证码错误')
        else:
            session['logged_in'] = True
            session['username'] = user.username
            return redirect(url_for('dashboard'))

        # print(f'request_captcha = {request.form['captcha']}')
        # print(f'session_captcha = {session.get('captcha')}')

        # 携带新验证码到模板
        captcha = new_captcha

    else:  # GET请求
        captcha = generate_captcha()
        session['captcha'] = captcha

    return render_template('login.html', error=error, captcha=captcha)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        if User.query.filter_by(username=request.form['username']).first():
            error = 'Username already exists'
        else:
            hashed_pw = generate_password_hash(request.form['password'])
            new_user = User(username=request.form['username'], password=hashed_pw,
                            email=request.form['email'], phone=request.form['phone'])
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('register.html', error=error)


@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)