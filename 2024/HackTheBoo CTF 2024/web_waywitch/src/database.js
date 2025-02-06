const sqlite = require("sqlite-async");
const fs = require("fs");

class Database {
  constructor(db_file) {
    this.db_file = db_file;
    this.db = undefined;
  }

  async connect() {
    this.db = await sqlite.open(this.db_file);
  }

  async migrate() {
    let flag;
    fs.readFile("/flag.txt", "utf8", function (err, data) {
      flag = data;
    });

    await this.db.exec(`
          DROP TABLE IF EXISTS tickets;

          CREATE TABLE tickets(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name VARCHAR(255) NOT NULL,
              username VARCHAR(255) NOT NULL,
              content TEXT NOT NULL
          );
      `);

    await this.db.exec(`
          INSERT INTO tickets (name, username, content) VALUES
          ('John Doe', 'guest_1234', 'I need help with my account.'),
          ('Jane Smith', 'guest_5678', 'There is an issue with my subscription.'),
          ('Admin', 'admin', 'Top secret: The Halloween party is at the haunted mansion this year. Use this code to enter ${flag}'),
          ('Paul Blake', 'guest_9012', 'Can someone assist with resetting my password?'),
          ('Alice Cooper', 'guest_3456', 'The app crashes every time I try to upload a picture.');
      `);
  }

  async add_ticket(name, username, content) {
    return new Promise(async (resolve, reject) => {
      try {
        let stmt = await this.db.prepare(
          "INSERT INTO tickets (name, username, content) VALUES (?, ?, ?)",
        );
        resolve(await stmt.run(name, username, content));
      } catch (e) {
        reject(e);
      }
    });
  }

  async get_tickets() {
    return new Promise(async (resolve, reject) => {
      try {
        let stmt = await this.db.prepare("SELECT * FROM tickets");
        resolve(await stmt.all());
      } catch (e) {
        reject(e);
      }
    });
  }
}

module.exports = Database;
