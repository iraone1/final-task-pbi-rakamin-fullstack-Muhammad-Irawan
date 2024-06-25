package main

import (
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB
var secretKey = []byte("secret_key")

type User struct {
	ID        uint   `gorm:"primarykey"`
	Username  string `gorm:"unique;not null"`
	Email     string `gorm:"unique;not null"`
	Password  string `gorm:"not null;minlength:6"`
	Photos    []Photo
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Photo struct {
	ID        uint   `gorm:"primarykey"`
	Title     string `gorm:"not null"`
	Caption   string
	PhotoURL  string `gorm:"not null"`
	UserID    uint   `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func main() {
	r := gin.Default()

	initDB()

	r.POST("/users/register", registerUser)
	r.POST("/users/login", loginUser)
	r.PUT("/users/:userId", updateUser)
	r.DELETE("/users/:userId", deleteUser)

	r.POST("/photos", createPhoto)
	r.GET("/photos", getPhotos)
	r.PUT("/photos/:photoId", updatePhoto)
	r.DELETE("/photos/:photoId", deletePhoto)

	r.Run(":8081")
}

func initDB() {
	dsn := "root:@tcp(localhost:3306)/api?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Gagal Menghubungkan database")
	}

	db.AutoMigrate(&User{}, &Photo{})

	DB = db
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func registerUser(c *gin.Context) {
	var newUser User
	if err := c.ShouldBindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	hashedPassword, err := hashPassword(newUser.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	newUser.Password = hashedPassword

	if err := DB.Create(&newUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat Pengguna"})
		return
	}

	c.JSON(http.StatusOK, newUser)
}

func loginUser(c *gin.Context) {
	var credentials struct {
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&credentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var user User
	if err := DB.Where("email = ?", credentials.Email).First(&user).Error; err != nil || !checkPasswordHash(credentials.Password, user.Password) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Pengguna tidak ditemukan"})
		return
	}

	// Check password

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id": user.ID,
		// Add other claims if needed
	})

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func updateUser(c *gin.Context) {
	userID := c.Param("userId")

	var updatedUser User
	if err := c.ShouldBindJSON(&updatedUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var user User
	if err := DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Pengguna tidak ditemukan "})
		return
	}

	if err := DB.Model(&user).Updates(&updatedUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memperbarui pengguna"})
		return
	}

	c.JSON(http.StatusOK, updatedUser)
}

func deleteUser(c *gin.Context) {
	userID := c.Param("userId")

	var user User
	if err := DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Pengguna tidak ditemukan"})
		return
	}

	if err := DB.Delete(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus pengguna"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Pengguna telah dihapus"})
}

func createPhoto(c *gin.Context) {
	var newPhoto Photo
	if err := c.ShouldBindJSON(&newPhoto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	userID := getUserIDFromToken(c)

	newPhoto.UserID = userID

	if err := DB.Create(&newPhoto).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat foto"})
		return
	}

	c.JSON(http.StatusOK, newPhoto)
}

func getPhotos(c *gin.Context) {
	var photos []Photo
	if err := DB.Find(&photos).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat foto"})
		return
	}

	c.JSON(http.StatusOK, photos)
}

func updatePhoto(c *gin.Context) {
	photoID := c.Param("photoId")

	var updatedPhoto Photo
	if err := c.ShouldBindJSON(&updatedPhoto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var photo Photo
	if err := DB.First(&photo, photoID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Foto tidak ditemukan"})
		return
	}

	userID := getUserIDFromToken(c)
	if photo.UserID != userID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Foto tidak bisa diperbarui karena tidak memiliki hak"})
		return
	}

	if err := DB.Model(&photo).Updates(&updatedPhoto).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal diperbarui foto"})
		return
	}

	c.JSON(http.StatusOK, updatedPhoto)
}

func deletePhoto(c *gin.Context) {
	photoID := c.Param("photoId")

	var photo Photo
	if err := DB.First(&photo, photoID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "foto tidak ditemukan"})
		return
	}

	userID := getUserIDFromToken(c)
	if photo.UserID != userID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Foto tidak bisa dihapus karena tidak memiliki hak"})
		return
	}

	if err := DB.Delete(&photo).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus foto"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Foto Terhapus"})
}

func getUserIDFromToken(c *gin.Context) uint {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		return 0
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return 0
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return 0
	}

	userID, ok := claims["id"].(float64)
	if !ok {
		return 0
	}

	return uint(userID)
}
