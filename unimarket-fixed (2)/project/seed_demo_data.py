from pathlib import Path
import sqlite3, time, secrets, hashlib
ROOT=Path(__file__).resolve().parent
DB=ROOT/'database'/'unimarket.sqlite3'

def password_hash(password):
    salt=secrets.token_bytes(16); digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,260000)
    return 'pbkdf2_sha256$260000$'+salt.hex()+'$'+digest.hex()

universities=['Catholic University of Eastern Africa','University of Nairobi','Kenyatta University','Strathmore University']
categories=[
 ('Textbooks and Notes',1200,'Used - Good','demo-1.svg'),
 ('Electronics and Gadgets',3500,'Used - Excellent','demo-2.svg'),
 ('Clothes and Accessories',1800,'Used - Good','demo-3.svg'),
 ('Event Tickets',800,'New','demo-4.svg'),
 ('Services',2500,'Available','demo-5.svg'),
]
# 4 sellers x 10 listings each, with a varied category rotation
sellers=[('Amina Wanjiku','amina.seller@demo.unimarket.test'),('Brian Otieno','brian.seller@demo.unimarket.test'),('Cynthia Mwende','cynthia.seller@demo.unimarket.test'),('David Kiptoo','david.seller@demo.unimarket.test')]
buyers=[('Ethan Njoroge','ethan.buyer@demo.unimarket.test'),('Faith Achieng','faith.buyer@demo.unimarket.test'),('Grace Muthoni','grace.buyer@demo.unimarket.test'),('Hassan Ali','hassan.buyer@demo.unimarket.test'),('Irene Chebet','irene.buyer@demo.unimarket.test'),('Joel Kamau','joel.buyer@demo.unimarket.test')]
conn=sqlite3.connect(DB); conn.row_factory=sqlite3.Row
now=int(time.time())
# ensure schema is current when script is run directly
schema=(ROOT/'database'/'schema.sql').read_text(); conn.executescript(schema)
for name,email in sellers+buyers:
    role='seller' if (name,email) in sellers else 'buyer'
    conn.execute('''INSERT OR IGNORE INTO users(name,email,phone,university,faculty,year,bio,role,password_hash,email_verified,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)''', (name,email,'+254700000000',universities[len(name)%len(universities)],'School of Science','Year 3','Demo account for UniMarket testing.',role,password_hash('DemoPass123!'),1,now))
# Only seed listings if the demo set is not already present
existing=conn.execute("SELECT count(*) n FROM users WHERE email LIKE '%@demo.unimarket.test'").fetchone()['n']
if existing >= 10:
    sellers_rows=conn.execute("SELECT id,name FROM users WHERE email LIKE '%.seller@demo.unimarket.test' ORDER BY email").fetchall()
    title_words=[
      ('Calculus', 'clear notes and worked examples for revision'),('Programming', 'well-kept course text with useful margin notes'),('Statistics', 'compact reference copy for exam preparation'),('Database Systems', 'complete textbook with chapter summaries'),
      ('Wireless Headphones','tested battery and clean ear cushions'),('Scientific Calculator','fully working calculator with fresh battery'),('USB-C Hub','portable multiport adapter for study setups'),('Laptop Stand','foldable aluminium stand for a desk'),
      ('Campus Hoodie','comfortable heavyweight hoodie in good condition'),('Backpack','durable student backpack with laptop sleeve'),('Running Shoes','lightly worn shoes suitable for campus walks'),('Denim Jacket','classic jacket with clean lining'),
      ('Freshers Concert','verified event ticket for the campus show'),('Graduation Dinner','reserved seat ticket for the annual dinner'),('Debate Night','entry pass for the interfaculty debate'),('Sports Final','spectator ticket for the university final'),
      ('Peer Tutoring','one-hour session for programming and maths'),('Portrait Photography','campus portrait session with edited photos'),('Graphic Design','poster and social media design service'),('CV Review','practical review and formatting for applications')]
    for si,srow in enumerate(sellers_rows):
        for j in range(10):
            cat,base,condition,img=categories[(si+j)%len(categories)]
            title,detail=title_words[(si*5+j)%len(title_words)]
            price=base + ((si*3+j*2)%5)*250
            desc=f'{detail.capitalize()}. Ideal for university students, inspected before posting, and available for a convenient campus handover.'
            image=f'/static/images/demo/{img}'
            conn.execute("INSERT INTO listings(user_id,title,category,description,price,condition,location,image_path,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (srow['id'],title,cat,desc,price,condition,'CUEA main campus',image,now+60*86400,now,now))
conn.commit(); print('demo users:', conn.execute("SELECT count(*) n FROM users WHERE email LIKE '%@demo.unimarket.test'").fetchone()['n']); print('demo listings:', conn.execute("SELECT count(*) n FROM listings l JOIN users u ON u.id=l.user_id WHERE u.email LIKE '%.seller@demo.unimarket.test'").fetchone()['n'])
