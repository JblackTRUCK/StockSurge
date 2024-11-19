from flask import render_template 
from flask import Flask, request, jsonify
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import feedparser
import random
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, 
    get_jwt_identity, decode_token
)
from functools import wraps
import jwt
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
api = Api(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stock_trading.db'
app.config['JWT_SECRET_KEY'] = '868966f2453ed9f423176a11a5ae800c32b92b965408dafbc1fce622a20672dc'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Short-lived tokens
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database and JWT
db = SQLAlchemy(app)
jwt = JWTManager(app)

@jwt.invalid_token_loader
def invalid_token_callback(error_string):
    logger.error(f"Invalid token: {error_string}")
    return jsonify({"msg": error_string}), 422

@app.route('/test', methods=['GET'])
@jwt_required()
def test():
    return jsonify({"msg": "Access granted"}), 200

# Model definitions
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    full_name = db.Column(db.String(100))
    role = db.Column(db.String(20), default='user')  # For RBAC
    is_mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(32))  # For TOTP-based MFA
    cash_balance = db.Column(db.Float, default=0.0)
    cash_account = db.relationship('CashAccount', backref='user', uselist=False)

class Stock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticker = db.Column(db.String(10), unique=True, nullable=False)
    company_name = db.Column(db.String(100), nullable=False)
    current_price = db.Column(db.Float, nullable=False)
    volume = db.Column(db.Integer, nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey('stock.id'), nullable=True)  # Nullable for deposits
    transaction_type = db.Column(db.String(10), nullable=False)  # 'buy', 'sell', or 'deposit'
    quantity = db.Column(db.Integer, nullable=True)  # Nullable for deposits
    price = db.Column(db.Float, nullable=True)  # Nullable for deposits
    amount = db.Column(db.Float, nullable=True)  # For deposits
    payment_method = db.Column(db.String(20), nullable=True)  # For deposits
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class CashAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)

class Portfolio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey('stock.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

class MarketHours(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    open_time = db.Column(db.Time, nullable=False)
    close_time = db.Column(db.Time, nullable=False)

class MarketSchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    trading_days = db.Column(db.String(50), nullable=False)  # Comma-separated list of days

# Helper functions
def role_required(role):
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)
            if user.role == role:
                return fn(*args, **kwargs)
            else:
                return jsonify({"msg": "Insufficient permissions"}), 403
        return decorator
    return wrapper

def check_token_payload(token):
    try:
        payload = decode_token(token)
        logger.debug(f"Token payload: {payload}")
        return payload
    except jwt.ExpiredSignatureError:
        logger.error("Token has expired")
        return None
    except jwt.InvalidTokenError:
        logger.error("Invalid token")
        return None

# Routes

@app.route('/api/auth/status', methods=['GET'])
@jwt_required()
def auth_status():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return jsonify({
        'authenticated': True,
        'user': {
            'username': user.username,
            'cash_balance': user.cash_balance
        }
    }), 200

# Move this route to be with the other routes, before if __name__ == '__main__':
@app.route('/api/news')
def get_news():
    try:
        feeds = [
            "https://www.marketwatch.com/site/rss",
            "https://www.cnbc.com/id/10001147/device/rss/rss.html",
            "https://finance.yahoo.com/news/rssindex"
        ]
        
        all_entries = []
        for feed_url in feeds:
            feed = feedparser.parse(feed_url)
            for entry in feed.entries[:5]:  # Get first 5 entries from each feed
                # Try different possible field names for description
                description = None
                if hasattr(entry, 'description'):
                    description = entry.description
                elif hasattr(entry, 'summary'):
                    description = entry.summary
                elif hasattr(entry, 'content'):
                    description = entry.content[0].value if isinstance(entry.content, list) else entry.content
                
                if description:
                    all_entries.append({
                        'title': entry.title,
                        'description': description[:150] + '...' if len(description) > 150 else description,
                        'source': feed.feed.title if hasattr(feed.feed, 'title') else 'Financial News'
                    })
        
        # Make sure we have at least one entry
        if not all_entries:
            # Provide fallback news items
            all_entries = [
                {
                    'title': 'Markets Update',
                    'description': 'Stay tuned for the latest market updates and financial news.',
                    'source': 'Stock Surge'
                },
                {
                    'title': 'Trading News',
                    'description': 'Market analysis and trading insights coming soon.',
                    'source': 'Stock Surge'
                },
                {
                    'title': 'Financial Headlines',
                    'description': 'Latest financial headlines and market movements.',
                    'source': 'Stock Surge'
                }
            ]
        
        # Randomly select 3 entries
        selected_entries = random.sample(all_entries, min(3, len(all_entries)))
        return jsonify(selected_entries)
        
    except Exception as e:
        app.logger.error(f"Error fetching news: {str(e)}")
        # Return fallback news items on error
        fallback_news = [
            {
                'title': 'Markets Update',
                'description': 'Stay tuned for the latest market updates and financial news.',
                'source': 'Stock Surge'
            },
            {
                'title': 'Trading News',
                'description': 'Market analysis and trading insights coming soon.',
                'source': 'Stock Surge'
            },
            {
                'title': 'Financial Headlines',
                'description': 'Latest financial headlines and market movements.',
                'source': 'Stock Surge'
            }
        ]
        return jsonify(fallback_news)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(
        username=data['username'],
        email=data['email'],
        password_hash=hashed_password,
        full_name=data['full_name'],
        role='user'  # Default role
    )
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'New user created!'}), 201
    except IntegrityError as e:
        db.session.rollback()
        if 'UNIQUE constraint failed: user.username' in str(e):
            return jsonify({'message': 'Username already exists'}), 400
        elif 'UNIQUE constraint failed: user.email' in str(e):
            return jsonify({'message': 'Email already exists'}), 400
        else:
            app.logger.error(f"Error in user registration: {str(e)}")
            return jsonify({'message': 'Something went wrong during registration'}), 500
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Unexpected error in user registration: {str(e)}")
        return jsonify({'message': 'An unexpected error occurred'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    logger.debug(f"Login attempt for username: {data.get('username')}")
    
    user = User.query.filter_by(username=data['username']).first()
    if not user:
        logger.warning(f"User not found: {data.get('username')}")
        return jsonify({'message': 'Invalid username or password'}), 401
    
    logger.debug(f"User found: {user.username}, checking password...")
    if check_password_hash(user.password_hash, data['password']):
        logger.info(f"Successful login for user: {user.username}")
        if user.is_mfa_enabled:
            temp_token = create_access_token(identity=user.id, expires_delta=timedelta(minutes=5))
            return jsonify({"message": "MFA required", "temp_token": temp_token}), 200
        else:
            access_token = create_access_token(identity=user.id)
            return jsonify(access_token=access_token), 200
    else:
        logger.warning(f"Invalid password for user: {user.username}")
        return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/api/portfolio', methods=['GET'])
@jwt_required()
def get_portfolio():
    try:
        current_user_id = get_jwt_identity()
        logger.debug(f"Decoded user ID: {current_user_id}")
        
        portfolio = Portfolio.query.filter_by(user_id=current_user_id).all()
        portfolio_data = []
        for item in portfolio:
            stock = Stock.query.get(item.stock_id)
            portfolio_data.append({
                'stock_ticker': stock.ticker,
                'quantity': item.quantity,
                'current_price': stock.current_price,
                'total_value': item.quantity * stock.current_price
            })
        logger.debug(f"Portfolio data: {portfolio_data}")
        return jsonify(portfolio_data), 200
    except jwt.exceptions.InvalidTokenError as e:
        logger.error(f"Token validation error: {str(e)}")
        return jsonify({"msg": "Invalid token"}), 422
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return jsonify({"msg": "Server error"}), 500

@app.route('/portfolio/value', methods=['GET'])
@jwt_required()
def get_portfolio_value():
    current_user_id = get_jwt_identity()
    portfolio = Portfolio.query.filter_by(user_id=current_user_id).all()
    total_value = sum(item.quantity * Stock.query.get(item.stock_id).current_price for item in portfolio)
    return jsonify({'total_value': total_value}), 200

@app.route('/transactions', methods=['GET'])
@jwt_required()
def get_transactions():
    current_user_id = get_jwt_identity()
    transactions = Transaction.query.filter_by(user_id=current_user_id).order_by(Transaction.timestamp.desc()).all()
    transactions_data = []
    for transaction in transactions:
        stock = Stock.query.get(transaction.stock_id)
        transactions_data.append({
            'id': transaction.id,
            'stock_ticker': stock.ticker,
            'transaction_type': transaction.transaction_type,
            'quantity': transaction.quantity,
            'price': transaction.price,
            'total_amount': transaction.quantity * transaction.price,
            'timestamp': transaction.timestamp.isoformat()
        })
    return jsonify(transactions_data), 200

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'message': 'The token has expired',
        'error': 'token_expired'
    }), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        'message': 'Authentication token is missing',
        'error': 'authorization_required'
    }), 401

@app.route('/api/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify(access_token=access_token)

@app.route('/api/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    # In a more complete implementation, you might want to blacklist the token
    return jsonify({"message": "Successfully logged out"}), 200

@app.route('/api/auth/check', methods=['GET'])
def check_auth():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return jsonify({"authenticated": False}), 401
    try:
        jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        return jsonify({"authenticated": True}), 200
    except:
        return jsonify({"authenticated": False}), 401

@app.route('/trade', methods=['POST'])
@jwt_required()
def trade_stock():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    app.logger.info(f"Trade attempted by user ID: {current_user_id}")
    app.logger.info(f"Trade details: {data}")
    
    # Validate input
    required_fields = ['stock_ticker', 'transaction_type', 'quantity']
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'Missing required fields'}), 400
    
    stock = Stock.query.filter_by(ticker=data['stock_ticker']).first()
    if not stock:
        return jsonify({'message': 'Stock not found'}), 404
    
    user = User.query.get(current_user_id)
    quantity = int(data['quantity'])
    
    app.logger.info(f"User balance: {user.cash_balance}")
    app.logger.info(f"Stock price: {stock.current_price}")
    
    if data['transaction_type'] == 'buy':
        total_cost = quantity * stock.current_price
        app.logger.info(f"Total cost of trade: {total_cost}")
        if user.cash_balance < total_cost:
            return jsonify({
                'message': 'Insufficient funds',
                'user_balance': user.cash_balance,
                'total_cost': total_cost,
                'stock_price': stock.current_price,
                'quantity': quantity
            }), 400
        
        user.cash_balance -= total_cost
        new_transaction = Transaction(
            user_id=current_user_id,
            stock_id=stock.id,
            transaction_type='buy',
            quantity=quantity,
            price=stock.current_price
        )
        db.session.add(new_transaction)
        
        portfolio_item = Portfolio.query.filter_by(user_id=current_user_id, stock_id=stock.id).first()
        if portfolio_item:
            portfolio_item.quantity += quantity
        else:
            new_portfolio_item = Portfolio(user_id=current_user_id, stock_id=stock.id, quantity=quantity)
            db.session.add(new_portfolio_item)
    
    elif data['transaction_type'] == 'sell':
        portfolio_item = Portfolio.query.filter_by(user_id=current_user_id, stock_id=stock.id).first()
        if not portfolio_item or portfolio_item.quantity < quantity:
            return jsonify({'message': 'Insufficient stocks to sell'}), 400
        
        total_sale = quantity * stock.current_price
        user.cash_balance += total_sale
        new_transaction = Transaction(
            user_id=current_user_id,
            stock_id=stock.id,
            transaction_type='sell',
            quantity=quantity,
            price=stock.current_price
        )
        db.session.add(new_transaction)
        
        portfolio_item.quantity -= quantity
        if portfolio_item.quantity == 0:
            db.session.delete(portfolio_item)
    
    else:
        return jsonify({'message': 'Invalid transaction type'}), 400

    db.session.commit()
    app.logger.info(f"Trade successful. New user balance: {user.cash_balance}")
    return jsonify({'message': f'Successfully {data["transaction_type"]} {quantity} shares of {stock.ticker}'}), 200

@app.route('/add_admin_user', methods=['POST'])
def add_admin_user():
    try:
        admin_user = User.query.filter_by(username='admin').first()
        if admin_user:
            return jsonify({'message': 'Admin user already exists', 'user_id': admin_user.id}), 200

        new_admin = User(
            username='admin',
            email='admin@example.com',
            full_name='Admin User',
            role='admin',
            cash_balance=100000.0
        )
        new_admin.password_hash = generate_password_hash('adminpassword123')
        db.session.add(new_admin)
        db.session.commit()
        
        return jsonify({'message': 'Admin user created successfully', 'user_id': new_admin.id}), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding admin user: {str(e)}")
        return jsonify({'message': f'Error adding admin user: {str(e)}'}), 500

@app.route('/admin/stocks', methods=['POST'])
@jwt_required()
def add_stock():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if user.role != 'admin':
        app.logger.warning(f"Non-admin user (ID: {current_user_id}) attempted to access admin endpoint")
        return jsonify({'message': 'Insufficient permissions'}), 403

    data = request.get_json()
    if not all(k in data for k in ('ticker', 'company_name', 'current_price', 'volume')):
        return jsonify({'message': 'Missing required fields'}), 400
    
    new_stock = Stock(
        ticker=data['ticker'],
        company_name=data['company_name'],
        current_price=data['current_price'],
        volume=data['volume']
    )
    db.session.add(new_stock)
    db.session.commit()
    app.logger.info(f"New stock added: {new_stock.ticker}")
    return jsonify({'message': 'New stock added successfully'}), 201

@app.route('/admin/market-hours', methods=['POST', 'PUT'])
@jwt_required()
def set_market_hours():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if user.role != 'admin':
        app.logger.warning(f"Non-admin user (ID: {current_user_id}) attempted to access admin endpoint")
        return jsonify({'message': 'Insufficient permissions'}), 403

    data = request.get_json()
    if not all(k in data for k in ('open_time', 'close_time')):
        return jsonify({'message': 'Missing required fields'}), 400
    
    market_hours = MarketHours.query.first()
    if not market_hours:
        market_hours = MarketHours()
        db.session.add(market_hours)
    
    market_hours.open_time = datetime.strptime(data['open_time'], '%H:%M').time()
    market_hours.close_time = datetime.strptime(data['close_time'], '%H:%M').time()
    db.session.commit()
    return jsonify({'message': 'Market hours updated successfully'}), 200

@app.route('/api/deposit', methods=['POST'])
@jwt_required()
def process_deposit():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        data = request.get_json()
        amount = float(data['amount'])
        payment_method = data['payment_method']
        
        if amount <= 0:
            return jsonify({'message': 'Invalid deposit amount'}), 400
            
        # Update user balance
        user.cash_balance += amount
        
        # Create a transaction record
        transaction = Transaction(
            user_id=current_user_id,
            transaction_type='deposit',
            amount=amount,
            payment_method=payment_method
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        logger.info(f"Deposit successful for user {user.username}. Amount: ${amount}, New balance: ${user.cash_balance}")
        
        return jsonify({
            'message': 'Deposit successful',
            'new_balance': user.cash_balance,
            'transaction_id': transaction.id
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error processing deposit: {str(e)}")
        return jsonify({'message': 'Error processing deposit'}), 500

@app.route('/api/withdraw', methods=['POST'])
@jwt_required()
def process_withdrawal():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        data = request.get_json()
        amount = float(data['amount'])
        payment_method = data['payment_method']
        
        if amount <= 0:
            return jsonify({'message': 'Invalid withdrawal amount'}), 400
            
        if user.cash_balance < amount:
            return jsonify({'message': 'Insufficient funds'}), 400
            
        # Update user balance
        user.cash_balance -= amount
        
        # Create a transaction record
        transaction = Transaction(
            user_id=current_user_id,
            transaction_type='withdraw',
            amount=amount,
            payment_method=payment_method
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        logger.info(f"Withdrawal successful for user {user.username}. Amount: ${amount}, New balance: ${user.cash_balance}")
        
        return jsonify({
            'message': 'Withdrawal successful',
            'new_balance': user.cash_balance,
            'transaction_id': transaction.id
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error processing withdrawal: {str(e)}")
        return jsonify({'message': 'Error processing withdrawal'}), 500

@app.route('/admin/market-schedule', methods=['POST', 'PUT'])
@jwt_required()
def set_market_schedule():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if user.role != 'admin':
        app.logger.warning(f"Non-admin user (ID: {current_user_id}) attempted to access admin endpoint")
        return jsonify({'message': 'Insufficient permissions'}), 403

    data = request.get_json()
    if 'trading_days' not in data:
        return jsonify({'message': 'Missing required fields'}), 400
    
    market_schedule = MarketSchedule.query.first()
    if not market_schedule:
        market_schedule = MarketSchedule()
        db.session.add(market_schedule)
    
    market_schedule.trading_days = ','.join(data['trading_days'])
    db.session.commit()
    return jsonify({'message': 'Market schedule updated successfully'}), 200

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return jsonify(logged_in_as=user.username), 200

@app.route('/admin', methods=['GET'])
@role_required('admin')
def admin():
    return jsonify({"msg": "Welcome to the admin area"}), 200

@app.route('/user/balance', methods=['GET'])
@jwt_required()
def get_user_balance():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        app.logger.error(f"User not found for ID: {current_user_id}")
        return jsonify({'error': 'User not found'}), 404
    app.logger.info(f"Balance check for user ID {current_user_id}: {user.cash_balance}")
    return jsonify({'cash_balance': user.cash_balance, 'user_id': user.id, 'username': user.username}), 200

@app.route('/add_test_data', methods=['POST'])
def add_test_data():
    try:
        # Find or create the w0lfgang user
        w0lfgang_user = User.query.filter_by(username='w0lfgang').first()
        
        if not w0lfgang_user:
            # Create new user with proper password hash
            w0lfgang_user = User(
                username='w0lfgang',
                email='w0lfgang@example.com',
                full_name='Wolfgang Test',
                role='user',
                cash_balance=100000.0,
                password_hash=generate_password_hash('password123', method='pbkdf2:sha256')
            )
            db.session.add(w0lfgang_user)
            app.logger.info(f"Created new w0lfgang user")
        else:
            # Update existing user
            w0lfgang_user.cash_balance = 100000.0
            w0lfgang_user.password_hash = generate_password_hash('password123', method='pbkdf2:sha256')
            app.logger.info(f"Updated existing w0lfgang user with ID: {w0lfgang_user.id}")

        # Add some test stocks if they don't exist
        stocks_data = [
            {'ticker': 'AAPL', 'company_name': 'Apple Inc.', 'current_price': 150.0, 'volume': 1000000},
            {'ticker': 'GOOG', 'company_name': 'Alphabet Inc.', 'current_price': 2800.0, 'volume': 500000}
        ]
        stocks = []
        for stock_data in stocks_data:
            stock = Stock.query.filter_by(ticker=stock_data['ticker']).first()
            if not stock:
                stock = Stock(**stock_data)
                db.session.add(stock)
                app.logger.info(f"Test stock added: {stock.ticker}")
            else:
                stock.current_price = stock_data['current_price']
                stock.volume = stock_data['volume']
                app.logger.info(f"Stock {stock.ticker} updated")
            stocks.append(stock)

        db.session.flush()

        # Add or update portfolio items for w0lfgang
        for stock in stocks:
            portfolio_item = Portfolio.query.filter_by(user_id=w0lfgang_user.id, stock_id=stock.id).first()
            if portfolio_item:
                portfolio_item.quantity += 10
                app.logger.info(f"Updated portfolio item for {stock.ticker}")
            else:
                new_portfolio_item = Portfolio(user_id=w0lfgang_user.id, stock_id=stock.id, quantity=10)
                db.session.add(new_portfolio_item)
                app.logger.info(f"Added new portfolio item for {stock.ticker}")

        # Commit all changes
        db.session.commit()

        return jsonify({
            'message': 'Test data added successfully',
            'user': {
                'id': w0lfgang_user.id,
                'username': w0lfgang_user.username,
                'cash_balance': w0lfgang_user.cash_balance
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding test data: {str(e)}")
        return jsonify({'message': f'Error adding test data: {str(e)}'}), 500

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/portfolio')
def portfolio_page():
    return render_template('portfolio.html')

@app.route('/trading')
def trading():
    return render_template('trading.html')

@app.route('/transaction_history')
def transaction_history():
    return render_template('transaction_history.html')

@app.route('/deposit_cash')
def deposit_cash():
    return render_template('deposit_cash.html')

@app.route('/withdraw_cash')
def withdraw_cash():
    return render_template('withdraw_cash.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/new_account')
def new_account():
    return render_template('new_account.html')

@app.route('/cash_management')
def cash_management():
    return render_template('cash_management.html')

@app.route('/submit_trade')
def submit_trade():
    return render_template('submit_trade.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables before running the app
    app.run(debug=True)


