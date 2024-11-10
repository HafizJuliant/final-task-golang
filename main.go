package main

import (
	"final-task-golang/handler"
	"final-task-golang/middleware"
	"log"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	// Env
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file", err)
	}

	// Database
	db := NewDatabase()
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatal("failed to get DB from GORM:", err)
	}
	defer sqlDB.Close()

	// secret-key
	signingKey := os.Getenv("SIGNING_KEY")

	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"}, // Replace with your frontend's URL
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// grouping route with /auth
	authHandler := handler.NewAuth(db, []byte(signingKey))
	authRoute := r.Group("/auth")
	authRoute.POST("/login", authHandler.Login)
	authRoute.POST("/upsert", authHandler.Upsert)
	authRoute.POST("/change-password", middleware.AuthMiddleware(signingKey), authHandler.ChangePassword)

	// grouping route with /account
	accountHandler := handler.NewAccount(db)
	accountRoutes := r.Group("/account")
	accountRoutes.POST("/create", accountHandler.Create)
	accountRoutes.GET("/read/:id", accountHandler.Read)
	accountRoutes.PATCH("/update/:id", accountHandler.Update)
	accountRoutes.DELETE("/delete/:id", accountHandler.Delete)
	accountRoutes.GET("/list", accountHandler.List)
	accountRoutes.POST("/topup", accountHandler.TopUp)

	// middleware := middleware.AuthMiddleware(signingKey)
	accountRoutes.GET("/my", middleware.AuthMiddleware(signingKey), accountHandler.My)
	accountRoutes.GET("/balance", middleware.AuthMiddleware(signingKey), accountHandler.Balance)
	accountRoutes.POST("/transfer", middleware.AuthMiddleware(signingKey), accountHandler.Transfer)
	accountRoutes.GET("/mutation", middleware.AuthMiddleware(signingKey), accountHandler.Mutation)
	accountRoutes.GET("/statistics", middleware.AuthMiddleware(signingKey), accountHandler.Statistics)

	// grouping route with /transaction-category
	transaction_categoryHandler := handler.NewTransCat(db)
	transaction_categoryRoutes := r.Group("/transaction-category")
	transaction_categoryRoutes.POST("/create", transaction_categoryHandler.Create)
	transaction_categoryRoutes.GET("/read/:id", transaction_categoryHandler.Read)
	transaction_categoryRoutes.PATCH("/update/:id", transaction_categoryHandler.Update)
	transaction_categoryRoutes.DELETE("/delete/:id", transaction_categoryHandler.Delete)
	transaction_categoryRoutes.GET("/list", transaction_categoryHandler.List)

	transaction_categoryRoutes.GET("/my", middleware.AuthMiddleware(signingKey), transaction_categoryHandler.My)

	transactionHandler := handler.NewTrans(db)
	transactionRoutes := r.Group("/transaction")
	transactionRoutes.POST("/new", transactionHandler.NewTransaction)
	transactionRoutes.GET("/list", transactionHandler.TransactionList)

	r.Run(":8081") // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}

func NewDatabase() *gorm.DB {
	// dsn := "host=localhost port=5432 user=postgres dbname=digi sslmode=disable TimeZone=Asia/Jakarta"
	dsn := os.Getenv("DATABASE")
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("failed to get DB object: %v", err)
	}

	var currentDB string
	err = sqlDB.QueryRow("SELECT current_database()").Scan(&currentDB)
	if err != nil {
		log.Fatalf("failed to query current database: %v", err)
	}

	log.Printf("Current Database: %s\n", currentDB)

	return db
}