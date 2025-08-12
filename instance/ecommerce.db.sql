BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "cart_item" (
	"id"	INTEGER NOT NULL,
	"user_id"	INTEGER NOT NULL,
	"product_id"	INTEGER NOT NULL,
	"quantity"	INTEGER,
	PRIMARY KEY("id"),
	FOREIGN KEY("product_id") REFERENCES "product"("id"),
	FOREIGN KEY("user_id") REFERENCES "user"("id")
);
CREATE TABLE IF NOT EXISTS "order" (
	"id"	INTEGER NOT NULL,
	"user_id"	INTEGER NOT NULL,
	"total"	FLOAT NOT NULL,
	"status"	VARCHAR(20),
	"payment_method"	VARCHAR(50),
	PRIMARY KEY("id"),
	FOREIGN KEY("user_id") REFERENCES "user"("id")
);
CREATE TABLE IF NOT EXISTS "product" (
	"id"	INTEGER NOT NULL,
	"name"	VARCHAR(100) NOT NULL,
	"price"	FLOAT NOT NULL,
	"description"	TEXT NOT NULL,
	"image_url"	VARCHAR(200) NOT NULL,
	"stock"	INTEGER,
	"category"	VARCHAR(50),
	PRIMARY KEY("id")
);
CREATE TABLE IF NOT EXISTS "user" (
	"id"	INTEGER NOT NULL,
	"username"	VARCHAR(50) NOT NULL,
	"email"	VARCHAR(120) NOT NULL,
	"password_hash"	VARCHAR(128) NOT NULL,
	"is_admin"	BOOLEAN,
	UNIQUE("email"),
	PRIMARY KEY("id"),
	UNIQUE("username")
);
INSERT INTO "product" VALUES (1,'Wireless Headphones',129.99,'Premium noise-cancelling wireless headphones','https://via.placeholder.com/300',50,'Electronics');
INSERT INTO "product" VALUES (2,'Smart Watch',199.99,'Latest model with health tracking features','https://via.placeholder.com/300',30,'Electronics');
INSERT INTO "product" VALUES (3,'Running Shoes',89.99,'Comfortable running shoes with cushioning','https://via.placeholder.com/300',100,'Sports');
INSERT INTO "user" VALUES (1,'admin','admin@example.com','scrypt:32768:8:1$3CgZfVOZfskY4B0h$14178089a775ff11003cd4d91d47788443694186795d9ee34879ab44f01852b54039e1a43d6b9f7e405362bd09a9464fd5527feb5fbb9ace2ead800d27089ab1',1);
COMMIT;
