package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"ravynel-control-plane/internal/scanning"
	"ravynel-control-plane/internal/store"
)

type Server struct {
	repo         store.Repository
	orchestrator *scanning.Orchestrator
}

func New(repo store.Repository, orchestrator *scanning.Orchestrator) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	server := &Server{repo: repo, orchestrator: orchestrator}
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(cors())
	_ = router.SetTrustedProxies(nil)
	router.GET("/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })
	router.GET("/v1/scans", server.listScans)
	router.POST("/v1/scans", server.startScan)
	router.POST("/v1/scans/:id/stop", server.stopScan)
	router.GET("/v1/agents", server.listAgents)
	router.GET("/v1/alerts", server.listAlerts)
	router.GET("/v1/assets", server.listAssets)
	router.GET("/v1/reports", server.listReports)
	return router
}

type startScanRequest struct {
	Range string `json:"range" binding:"required"`
}

func (s *Server) listScans(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"scans": s.repo.ListScans()})
}

func (s *Server) listAgents(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"agents": s.repo.ListAgents()})
}

func (s *Server) listAlerts(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"alerts": []any{}})
}

func (s *Server) listAssets(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"assets": s.repo.ListAssets()})
}

func (s *Server) listReports(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"reports": []any{}})
}

func (s *Server) startScan(c *gin.Context) {
	var request startScanRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "range is required"})
		return
	}
	scan := s.orchestrator.StartNetworkScan(request.Range)
	c.JSON(http.StatusAccepted, scan)
}

func (s *Server) stopScan(c *gin.Context) {
	if !s.orchestrator.StopScan(c.Param("id")) {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not running"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "stopping"})
}

func cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
