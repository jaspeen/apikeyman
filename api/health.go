package api

import (
	"github.com/gin-gonic/gin"
)

func (a *Api) HealthLiveness(c *gin.Context) {
	c.JSON(200, gin.H{"status": "ok"})
}

func (a *Api) HealthReadiness(c *gin.Context) {
	err := a.Db.Ping()
	if err != nil {
		c.JSON(500, gin.H{"status": "error"})
	} else {
		c.JSON(200, gin.H{"status": "ok"})
	}
}

func (a *Api) HealthMetrics(c *gin.Context) {
	c.JSON(200, gin.H{})
}
