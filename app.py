from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory
import mysql.connector
import io
import base64
import hashlib
from PIL import Image
import os
from moviepy.editor import *


app = Flask(__name__)
app.secret_key = "your_secret_key"

# Connect to the database
conn = mysql.connector.connect(
    host="localhost",
    user="eshwarsriramoju",
    password="Eshu@1503",
)
c = conn.cursor()

c.execute("CREATE DATABASE IF NOT EXISTS yourdatabase")
conn.commit()

conn.database = 'yourdatabase'

# Create table if not exists
c.execute('''CREATE TABLE IF NOT EXISTS images
             (id INT AUTO_INCREMENT PRIMARY KEY, image MEDIUMBLOB, email VARCHAR(255))''')

c.execute('''CREATE TABLE IF NOT EXISTS users
             (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255), email VARCHAR(255), password VARCHAR(255))''')

c.execute('''CREATE TABLE IF NOT EXISTS audio2
                (id INT AUTO_INCREMENT PRIMARY KEY, audio_name VARCHAR(255), audio_blob LONGBLOB)''')

conn.commit()


from pydub import AudioSegment


def convert_audio_blob_to_mp3(audio_blob):
    # Load audio from the blob data
    audio = AudioSegment.from_file(io.BytesIO(audio_blob))
    audio.export("bgm.mp3", format="mp3")
# Function to save image to database
def save_image_to_db(image_data, email):
    sql = "INSERT INTO images (image, email) VALUES (%s, %s)"
    c.execute(sql, (image_data, email))
    conn.commit()

def store_selected_images_in_db(image_data):
    c.execute("INSERT INTO selected_images (image) VALUES (%s)", (image_data,))
    conn.commit()
    print("Image stored in the database")

def decode_base64_image(image_base64):
    # Remove the 'data:image;base64,' prefix from the Base64 string
    base64_data = image_base64.split(',', 1)[1]
    # Decode the Base64 string into binary image data
    image_data = base64.b64decode(base64_data)
    return image_data

def get_images_from_db(email):
    c.execute("SELECT image FROM images WHERE email=%s", (email,))
    images = c.fetchall()
    return images

def get_user_data():
    c.execute("SELECT name, email FROM users")
    users = c.fetchall()
    user_data = [{'name': row[0], 'email': row[1]} for row in users]
    return user_data

# Function to authenticate user login
def login(email, password):
    # Hash the password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    # Query the database for the user
    c.execute("SELECT * FROM users WHERE email=%s AND password=%s", (email, hashed_password))
    user = c.fetchone()
    
    if user:
        print("Login successful!")
        return True
    else:
        print("Invalid email or password!")
        return False

def convert_blob_to_jpg(blob):
    image = Image.open(io.BytesIO(blob))

    if image.mode == 'RGBA':
        image = image.convert('RGB')
    image.save("photo.jpeg", "JPEG")
    
        
    return image

@app.route('/signup', methods=['GET','POST'])
def signup_page():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        retype_password = request.form['retype_password']
        
        # Check if passwords match
        if password != retype_password:
            return "Passwords do not match!"
        
        # Check if the user already exists in the database
        c.execute("SELECT * FROM users WHERE email=%s", (email,))
        existing_user = c.fetchone()
        if existing_user:
            return "User with this email already exists!"
        
        # Hash the password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        # Insert the user into the database
        c.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_password))
        conn.commit()
        return "Signup Successful"
    return render_template('signup.html')

@app.route('/')
def login_page():
    return render_template('landing.html')


@app.route('/login_page', methods=['GET','POST'])
def login_2():
    return render_template('login.html')

def is_admin(email, password):
    return email == "admin@admin" and password == "admin"

@app.route('/login', methods=['POST'])
def authenticate():
    email = request.form['email']
    password = request.form['password']

    if is_admin(email, password):
        # Set session variables for admin
        session['logged_in'] = True
        session['email'] = email
        session['password'] = password
        return redirect('/admin')

    if login(email, password):
        session['logged_in'] = True
        session['email'] = email
        return redirect('/gallery')
    else:
        return "Invalid username or password"
    
@app.route('/admin', methods=['GET','POST'])
def admin_page():
    return render_template('admin.html', users=get_user_data())

@app.route('/gallery')
def show_gallery():
    if 'email' not in session:
        return redirect('/')
    email = session['email']
    images = get_images_from_db(email)
    image_urls = []
    for image in images:
        # Convert binary image data to base64 format for rendering in HTML
        image_data = image[0]
        image_base64 = base64.b64encode(image_data).decode('utf-8')
        image_urls.append('data:image;base64,' + image_base64)
    return render_template('uploadImages.html', image_urls=image_urls)

@app.route('/upload', methods=['POST'])
def upload_images():
    if 'email' not in session:
        return redirect('/')
    email = session['email']
    if 'images' not in request.files:
        return 'No file part'
    images = request.files.getlist('images')
    if not any(images):
        return redirect(url_for('show_gallery'))
    for image in images:
        image_data = image.read()
        save_image_to_db(image_data, email)
    return redirect(url_for('show_gallery'))

@app.route('/createVideo', methods=['GET', 'POST'])
def create_video():
    if 'email' not in session:
        return redirect('/')
    email = session['email']
    images = get_images_from_db(email)
    image_urls = []
    for image in images:
        # Convert binary image data to base64 format for rendering in HTML
        image_data = image[0]
        image_base64 = base64.b64encode(image_data).decode('utf-8')
        image_urls.append('data:image;base64,' + image_base64)

    c.execute("SELECT audio_name FROM audio2")
    audio_data = [row[0] for row in c.fetchall()]

    if request.method == 'POST':
        durations_raw = request.form.getlist('duration')
        durations_str = [x for x in durations_raw if x != 0]
        print(type(durations_str[0]))
        durations = [int(x) for x in durations_str]
        print(durations)
        blob_urls = request.form.getlist('selected_images')
        audio_name = request.form.get('audio')
        # print(type(audio_name))
        # print(audio_name)
        c.execute("SELECT audio_blob FROM audio2 WHERE audio_name = %s", (audio_name,))
        audio_blob = c.fetchone()[0]
        convert_audio_blob_to_mp3(audio_blob)
        
        # durations = []
        # for i in range(len(blob_urls)):
        #     durations.append(3)
        # print(durations)

        c.execute("""DROP TABLE IF EXISTS selected_images""")
        c.execute("""CREATE TABLE IF NOT EXISTS selected_images (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        image MEDIUMBLOB
                    )""")
        conn.commit()
        # print(blob_keys)
        for blob_url in blob_urls:
            image_data = decode_base64_image(blob_url)
            if image_data:
                store_selected_images_in_db(image_data)

        
        query = "SELECT id, image FROM selected_images"

        c.execute(query)

        clips = []
        # durations = [1, 2, 3, 4, 5]
        i = 0

        for (image_id, image_blob) in c:    
            img = convert_blob_to_jpg(image_blob)
            clip = ImageClip('photo.jpeg').set_duration(durations[i])
            clips.append(clip)
            i = i + 1

        audio = AudioFileClip("bgm.mp3")

        total_duration = sum(durations)
        start_time = 0  # Start at 10 seconds
        end_time = total_duration   # End at 30 seconds

        # Slice the audio clip
        audio = audio.subclip(start_time, end_time)

        # Write the sliced audio to a new file
        # sliced_audio.write_audiofile("bgm.mp3")
        os.remove("photo.jpeg")
        video_clip = concatenate_videoclips(clips, method="compose")
        video_clip.audio = audio
        video_clip.write_videofile("static/mix.mp4", fps=24, remove_temp=True, codec="libx264", audio_codec="aac")        
        os.remove("bgm.mp3")
                

        return redirect(url_for('generate_video'))

    return render_template('createVideo.html', image_urls=image_urls, audio_data=audio_data)

@app.route('/generate_video', methods=['POST', 'GET'])
def generate_video():
#     selected_images = []
#     image_urls = request.form.getlist('image_urls[]')
#     for i, image_url in enumerate(image_urls):
#         duration = request.form.get(f'duration_{i}')
#         selected = request.form.get(f'select_{i}')
#         if selected:
#             selected_images.append((image_url, duration))
#     # Process selected images and their durations to generate video
#     print(selected_images)  # Placeholder for video generation logic
    return render_template('show.html')


@app.route('/get_audio/<audio_name>')
def get_audio(audio_name):
    c.execute("SELECT audio_blob FROM audio2 WHERE audio_name = %s", (audio_name,))
    audio_blob = c.fetchone()[0]
    return audio_blob, 200, {'Content-Type': 'audio/mpeg'}



if __name__ == '__main__':
    app.run(debug=True)
