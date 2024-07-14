# Importing necessary modules from the Flask framework
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

# Creating an instance of the Flask class
app = Flask(__name__)

# Configure the SQLAlchemy connection string
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///acronyms.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the SQLAlchemy app
db = SQLAlchemy(app)

# Define the Acronym model
class Acronym(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    acronym = db.Column(db.String(10), unique=True, nullable=False)
    meaning = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(500))  # Allows for a longer description, nullable by default

# Defining a route for the root URL ('/')
@app.route('/')
def home():
    # Rendering the 'index.html' template when the root URL is accessed
    return render_template('index.html')

@app.route('/add', methods=['POST'])
def add_acronym():
    if request.method == 'POST':
        acronym = request.form['acronym'].upper()
        meaning = request.form['meaning']
        description = request.form['description']
        new_acronym = Acronym(acronym=acronym, meaning=meaning, description=description)
        db.session.add(new_acronym)
        db.session.commit()
        return redirect(url_for('home'))

@app.route('/acronyms', methods=['GET'])
def acronyms():
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Define how many items each page should display
    query = request.args.get('q', '')
    if query:
        acronyms = Acronym.query.filter(
            db.or_(
                Acronym.acronym.like('%' + query + '%'),
                Acronym.meaning.like('%' + query + '%'),
                Acronym.description.like('%' + query + '%')
            )
        ).paginate(page=page, per_page=per_page, error_out=False)
    else:
        acronyms = Acronym.query.order_by(Acronym.acronym).paginate(page=page, per_page=per_page, error_out=False)
    return render_template('acronyms.html', acronyms=acronyms.items, pagination=acronyms)

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_acronym(id):
    acronym = Acronym.query.get_or_404(id)
    if request.method == 'POST':
        acronym.acronym = request.form['acronym'].upper()
        acronym.meaning = request.form['meaning']
        acronym.description = request.form['description']
        db.session.commit()
        return redirect(url_for('acronyms'))
    return render_template('edit_acronym.html', acronym=acronym)

@app.route('/delete/<int:id>', methods=['GET'])
def delete_acronym(id):
    acronym = Acronym.query.get_or_404(id)
    db.session.delete(acronym)
    db.session.commit()
    return redirect(url_for('acronyms'))

# Checking if the script is run directly
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables for our data models within the application context
    app.run(debug=True)
