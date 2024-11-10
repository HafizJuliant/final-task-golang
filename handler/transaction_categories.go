package handler

import (
	"final-task-golang/model"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type TransCategInterface interface {
	Create(*gin.Context)
	Read(*gin.Context)
	Update(*gin.Context)
	Delete(*gin.Context)
	List(*gin.Context)

	My(*gin.Context)
}

type transcategImplement struct {
	db *gorm.DB
}

func NewTransCat(db *gorm.DB) TransCategInterface {
	return &transcategImplement{
		db: db,
	}
}

func (a *transcategImplement) Create(c *gin.Context) {
	payload := model.TransCat{}

	// bind JSON Request to payload
	err := c.BindJSON(&payload)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}

	// Create data
	result := a.db.Create(&payload)
	if result.Error != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": result.Error.Error(),
		})
		return
	}

	// Success response
	c.JSON(http.StatusOK, gin.H{
		"message": "Data succesfully added",
		"data":    payload,
	})
}

func (a *transcategImplement) Read(c *gin.Context) {
	var transcategImplement model.TransCat

	// get id from url transcatImplement/read/5, 5 will be the id
	id := c.Param("id")

	// Find first data based on id and put to transcatImplement model
	if err := a.db.First(&transcategImplement, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"error": "Not found",
			})
			return
		}

		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Success response
	c.JSON(http.StatusOK, gin.H{
		"data": transcategImplement,
	})
}

func (a *transcategImplement) Update(c *gin.Context) {
	payload := model.TransCat{}

	// bind JSON Request to payload
	err := c.BindJSON(&payload)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}

	// get id from url transcatImplement/update/5, 5 will be the id
	id := c.Param("id")

	// Find first data based on id and put to transcatImplement model
	transcategImplement := model.TransCat{}
	result := a.db.First(&transcategImplement, "transaction_category_id = ?", id)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"error": "Not found",
			})
			return
		}
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": result.Error.Error(),
		})
		return
	}

	// Update data
	transcategImplement.Name = payload.Name
	a.db.Save(transcategImplement)

	// Success response
	c.JSON(http.StatusOK, gin.H{
		"message": "Update success",
	})
}

func (a *transcategImplement) Delete(c *gin.Context) {
	// get id from url transcatImplement/delete/5, 5 will be the id
	id := c.Param("id")

	// Find first data based on id and delete it
	if err := a.db.Where("transaction_category_id = ?", id).Delete(&model.TransCat{}).Error; err != nil {
		// No data found and deleted
		if err == gorm.ErrRecordNotFound {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"error": "Not found",
			})
			return
		}
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Success response
	c.JSON(http.StatusOK, gin.H{
		"message": "Delete success",
		"data": map[string]string{
			"transaction_category_id": id,
		},
	})
}

func (a *transcategImplement) List(c *gin.Context) {
	// Prepare empty result
	var transcategImplements []model.TransCat

	// Find and get all transcatImplements data and put to &transcatImplements
	if err := a.db.Find(&transcategImplements).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Success response
	c.JSON(http.StatusOK, gin.H{
		"data": transcategImplements,
	})
}

func (a *transcategImplement) My(c *gin.Context) {
	var transcategImplement model.TransCat
	// get transaction_category_id from middleware auth
	transcategImplementID := c.GetInt64("transaction_category_id")

	// Find first data based on transaction_category_id given
	if err := a.db.First(&transcategImplement, transcategImplementID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"error": "Not found",
			})
			return
		}

		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Success response
	c.JSON(http.StatusOK, gin.H{
		"data": transcategImplement,
	})
}
