package main

import (
	"errors"
	"fmt"
	config2 "indigo-backend/config"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type User struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Token     string    `json:"token"`
	Notes     []Note    `json:"notes"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type LoginUser struct {
	Token string `json:"token" binding:"required`
}

type RegisterUser struct {
	Name  string `json:"name"  binding:"required"`
	Email string `json:"email" binding:"required,email"`
	Token string `json:"token" binding:"required"`
}

type Note struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Content   string    `json:"content"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type NoteDeleteInput struct {
	ID int `uri:"id" binding:"required"`
}

type NoteCreateInput struct {
	Content string `json:"content" binding:"required"`
}

func GenerateToken(userID int) (string, error) {

	claim := jwt.MapClaims{}
	claim["user_id"] = userID

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)

	signedToken, err := token.SignedString([]byte("bwastartup_secretkey"))

	if err != nil {
		return signedToken, err
	}

	return signedToken, nil
}

func ValidateToken(encodedToken string) (*jwt.Token, error) {
	token, err := jwt.Parse(encodedToken, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)

		if !ok {
			return nil, errors.New("invalid token")
		}
		return []byte("bwastartup_secretkey"), nil
	})

	if err != nil {
		return token, err
	}

	return token, nil
}

func main() {
	config2.SetEnv()
	dsn := "root@tcp(127.0.0.1:3306)/indigo?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})

	if err != nil {
		log.Fatal(err.Error())
		return
	}

	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins:  []string{"*"},
		AllowMethods:  []string{"PUT", "PATCH", "DELETE", "POST", "GET", "OPTIONS", "HEAD"},
		AllowHeaders:  []string{"Access-Control-Allow-Headers", "Access-Control-Allow-Origin", "Access-Control-Allow-Method", "Accept-Encoding", "Accept-Language", "Connection", "Host", "Referer", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "User-Agent", "Origin", "Accept", "X-Requested-With", "Content-Type", "Access-Control-Request-Method", "Access-Control-Request-Headers", "Authorization", "Access-Control-Allow-Origin"},
		ExposeHeaders: []string{"Authorization", "Content-Length"},
		MaxAge:        12 * time.Hour,
	}))

	r.POST("/login", func(c *gin.Context) {

		var input LoginUser
		var user User

		err := c.ShouldBindJSON(&input)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": err.Error(),
			})
			return
		}

		err = db.Where("token = ?", input.Token).Preload("Notes").Find(&user).Error
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": err.Error(),
			})
			return
		}

		if user.ID == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": "user not found",
			})
			return
		}

		token, err := GenerateToken(user.ID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"message": "success",
			"data":    user,
			"token":   token,
		})
	})

	// Register
	r.POST("/register", func(c *gin.Context) {

		var input RegisterUser
		var user User

		err := c.ShouldBindJSON(&input)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": err.Error(),
			})
			return
		}

		err = db.Where("token = ?", input.Token).Find(&user).Error
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": err.Error(),
			})
			return
		}

		if user.ID != 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": "token already exist",
			})
			return
		}

		err = db.Where("email = ?", input.Email).Find(&user).Error

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": err.Error(),
			})
			return
		}

		if user.ID != 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": "email already exist",
			})
			return
		}

		user.Name = input.Name
		user.Email = input.Email
		user.Token = input.Token

		err = db.Create(&user).Error
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": err.Error(),
			})
			return
		}

		token, err := GenerateToken(user.ID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "success",
			"data":    user,
			"token":   token,
		})
		return
	})

	// index
	r.GET("/note", authMiddleware(db), func(c *gin.Context) {
		currentUser := c.MustGet("currentUser").(User)

		db.Where("id = ?", currentUser.ID).Preload("Notes").Find(&currentUser)
		c.JSON(http.StatusOK, gin.H{
			"message": "success",
			"data":    currentUser,
		})
		return
	})

	// delete note
	r.DELETE("/note/:id", authMiddleware(db), func(c *gin.Context) {
		currentUser := c.MustGet("currentUser").(User)

		var input NoteDeleteInput
		err := c.ShouldBindUri(&input)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": err.Error(),
			})
			return
		}

		id := input.ID
		var note Note
		err = db.Where("id = ?", id).Find(&note).Error
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": err.Error(),
			})
			return
		}

		if note.UserID != currentUser.ID {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": "unathorized",
			})
			return
		}

		db.Delete(&Note{}, id)
		c.JSON(http.StatusOK, gin.H{
			"code":    http.StatusBadRequest,
			"message": "success deleting note",
		})
		return
	})

	// create note
	r.POST("/note/", authMiddleware(db), func(c *gin.Context) {

		currentUser := c.MustGet("currentUser").(User)

		var note Note
		var input NoteCreateInput
		err := c.ShouldBindJSON(&input)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": err.Error(),
			})
			return
		}

		note.Content = input.Content
		note.Status = "not yet"
		note.UserID = currentUser.ID
		note.CreatedAt = time.Now()

		err = db.Create(&note).Error
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "success creating a note",
			"data":    note,
		})
		return
	})

	r.Run()
}

func authMiddleware(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		if !strings.Contains(authHeader, "Bearer") {

			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "unauthorized",
			})
			return
		}

		// Bearer Token
		var tokenString = ""
		arrayToken := strings.Split(authHeader, " ")
		if len(arrayToken) == 2 {
			tokenString = arrayToken[1]
		}

		token, err := ValidateToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "unauthorized",
			})
			return
		}

		claim, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "unauthorized",
			})
			return
		}

		userID := int(claim["user_id"].(float64))

		fmt.Println(userID)

		var user User
		err = db.Where("id = ?", userID).Find(&user).Error

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "unauthorized",
			})
			return
		}

		if user.ID == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "unauthorized",
			})
			return
		}

		c.Set("currentUser", user)

	}

}
