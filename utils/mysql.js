const mysql = require('mysql2');
const mysqlPromise = require('mysql2/promise');

exports.pool = (host, database, user, password, limit = 5) => mysql.createPool({
    connectionLimit : limit,
    host, user, password, database,
    debug    :  false
});

exports.query = (pool, query) => {
    return new Promise ((resolve, reject) => {
      pool.query(query,(err, data) => {
        if(err) {
            console.error(err);
            return reject(err);
        }
        // rows fetch
        //console.log(data);
        return resolve(data);
    });
    })
}

exports.escape = str => mysql.escape(str);