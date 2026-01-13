package main

import (
	"database/sql"
	"fmt"
	"net/http"
	_ "github.com/lib/pq"
)

func queryHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 污点源 (Source): URL 参数
		userID := r.URL.Query().Get("id")

		// 漏洞点：SQL 注入 (SQL Injection)
		// 错误地使用了字符串格式化构建查询，而不是参数化查询
		query := fmt.Sprintf("SELECT username, email FROM users WHERE id = %s", userID)

		rows, err := db.Query(query) // Sink
		if err != nil {
			http.Error(w, "查询失败", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var username, email string
			if err := rows.Scan(&username, &email); err != nil {
				continue
			}
			fmt.Fprintf(w, "User: %s, Email: %s\n", username, email)
		}
	}
}

func main() {
	// 假设已初始化数据库连接
	db, _ := sql.Open("postgres", "user=pqgotest dbname=pqgotest sslmode=disable")
	http.HandleFunc("/user", queryHandler(db))
	http.ListenAndServe(":8080", nil)
}
