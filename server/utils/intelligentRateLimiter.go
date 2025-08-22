package utils

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"
)

// CircuitState represents the state of a circuit breaker
type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

// CircuitBreaker implements circuit breaker pattern for failing hosts
type CircuitBreaker struct {
	failureCount    int
	lastFailureTime time.Time
	state           CircuitState
	threshold       int           // Number of failures to trigger open state
	timeout         time.Duration // Time to wait before trying half-open
	mutex           sync.RWMutex
}

// IntelligentRateLimiter provides adaptive rate limiting with circuit breaker patterns
type IntelligentRateLimiter struct {
	dbPool        *pgxpool.Pool
	globalLimiter *rate.Limiter
	hostLimiters  map[string]*rate.Limiter
	hostMutex     sync.RWMutex

	// Adaptive rate limiting
	responseTimes  map[string][]time.Duration // Track response times per host
	errorRates     map[string]float64         // Track error rates per host
	backoffPeriods map[string]time.Time       // Track backoff periods per host
	adaptiveMutex  sync.RWMutex

	// Circuit breaker pattern
	circuitBreakers map[string]*CircuitBreaker
	circuitMutex    sync.RWMutex

	// Configuration
	globalRate        rate.Limit    // Global requests per second
	hostRate          rate.Limit    // Per-host requests per second
	burstSize         int           // Burst allowance
	adaptiveWindow    time.Duration // Window for adaptive adjustments
	circuitThreshold  int           // Failures to trigger circuit breaker
	backoffMultiplier float64       // Exponential backoff multiplier
	maxBackoff        time.Duration // Maximum backoff period

	// Metrics
	totalRequests    int64
	blockedRequests  int64
	circuitTrips     int64
	metricsStartTime time.Time
	metricsMutex     sync.RWMutex
}

// RateLimitStats represents rate limiting statistics
type RateLimitStats struct {
	Host            string        `json:"host"`
	RequestsAllowed int64         `json:"requests_allowed"`
	RequestsBlocked int64         `json:"requests_blocked"`
	AverageResponse time.Duration `json:"average_response"`
	ErrorRate       float64       `json:"error_rate"`
	CircuitState    string        `json:"circuit_state"`
	BackoffUntil    *time.Time    `json:"backoff_until,omitempty"`
	LastUpdated     time.Time     `json:"last_updated"`
}

// NewIntelligentRateLimiter creates a new intelligent rate limiter
func NewIntelligentRateLimiter(dbPool *pgxpool.Pool) *IntelligentRateLimiter {
	return &IntelligentRateLimiter{
		dbPool:            dbPool,
		globalLimiter:     rate.NewLimiter(rate.Limit(100.0/60.0), 5), // 100 requests per minute, burst of 5
		hostLimiters:      make(map[string]*rate.Limiter),
		responseTimes:     make(map[string][]time.Duration),
		errorRates:        make(map[string]float64),
		backoffPeriods:    make(map[string]time.Time),
		circuitBreakers:   make(map[string]*CircuitBreaker),
		globalRate:        rate.Limit(100.0 / 60.0), // 100 requests per minute
		hostRate:          rate.Limit(10.0 / 60.0),  // 10 requests per minute per host
		burstSize:         5,
		adaptiveWindow:    5 * time.Minute,
		circuitThreshold:  5,
		backoffMultiplier: 2.0,
		maxBackoff:        30 * time.Minute,
		metricsStartTime:  time.Now(),
	}
}

// CanProceed checks if a request can proceed based on rate limiting and circuit breaker state
func (irl *IntelligentRateLimiter) CanProceed(host, tool string) (bool, time.Duration) {
	// 1. Check circuit breaker state
	if breaker := irl.getCircuitBreaker(host); breaker != nil {
		if !breaker.canProceed() {
			irl.incrementBlockedRequests()
			return false, breaker.getWaitTime()
		}
	}

	// 2. Check global rate limit
	if !irl.globalLimiter.Allow() {
		reservation := irl.globalLimiter.Reserve()
		waitTime := reservation.DelayFrom(time.Now())
		irl.incrementBlockedRequests()
		return false, waitTime
	}

	// 3. Check per-host rate limit with adaptive adjustment
	hostLimiter := irl.getOrCreateHostLimiter(host)
	if !hostLimiter.Allow() {
		reservation := hostLimiter.Reserve()
		waitTime := reservation.DelayFrom(time.Now())
		irl.incrementBlockedRequests()
		return false, waitTime
	}

	// 4. Check backoff period for this host
	if backoffEnd := irl.getBackoffPeriod(host); !backoffEnd.IsZero() {
		if time.Now().Before(backoffEnd) {
			irl.incrementBlockedRequests()
			return false, time.Until(backoffEnd)
		}
		irl.clearBackoffPeriod(host)
	}

	irl.incrementTotalRequests()
	return true, 0
}

// RecordResponse records response metrics for adaptive rate limiting
func (irl *IntelligentRateLimiter) RecordResponse(host string, duration time.Duration, success bool) {
	irl.adaptiveMutex.Lock()
	defer irl.adaptiveMutex.Unlock()

	// Record response time
	if _, exists := irl.responseTimes[host]; !exists {
		irl.responseTimes[host] = make([]time.Duration, 0, 100)
	}

	// Keep only recent response times (sliding window)
	times := irl.responseTimes[host]
	if len(times) >= 100 {
		times = times[1:] // Remove oldest
	}
	times = append(times, duration)
	irl.responseTimes[host] = times

	// Update error rate
	irl.updateErrorRate(host, success)

	// Handle circuit breaker
	breaker := irl.getCircuitBreaker(host)
	if success {
		breaker.recordSuccess()
	} else {
		breaker.recordFailure()
		if breaker.shouldTrip() {
			irl.incrementCircuitTrips()
			log.Printf("[RATE_LIMITER] Circuit breaker tripped for host %s", host)
		}
	}

	// Apply adaptive rate limiting
	irl.adaptRateLimit(host)

	// Store metrics in database periodically
	go irl.storeMetrics(host)
}

// RecordError records an error for backoff calculation
func (irl *IntelligentRateLimiter) RecordError(host string, statusCode int) {
	// Apply exponential backoff for certain error codes
	if statusCode == 429 || statusCode == 503 || statusCode == 502 {
		irl.applyBackoff(host)
	}

	// Record as failed response for circuit breaker
	irl.RecordResponse(host, 0, false)
}

// getOrCreateHostLimiter gets or creates a rate limiter for a specific host
func (irl *IntelligentRateLimiter) getOrCreateHostLimiter(host string) *rate.Limiter {
	irl.hostMutex.RLock()
	limiter, exists := irl.hostLimiters[host]
	irl.hostMutex.RUnlock()

	if !exists {
		// Create new host limiter with adaptive rate
		adaptiveRate := irl.calculateAdaptiveRate(host)
		irl.hostMutex.Lock()
		limiter = rate.NewLimiter(adaptiveRate, irl.burstSize)
		irl.hostLimiters[host] = limiter
		irl.hostMutex.Unlock()
	}

	return limiter
}

// calculateAdaptiveRate calculates adaptive rate limit based on host performance
func (irl *IntelligentRateLimiter) calculateAdaptiveRate(host string) rate.Limit {
	irl.adaptiveMutex.RLock()
	defer irl.adaptiveMutex.RUnlock()

	baseRate := irl.hostRate

	// Adjust based on error rate
	if errorRate, exists := irl.errorRates[host]; exists {
		if errorRate > 0.1 { // More than 10% error rate
			baseRate = baseRate * 0.5 // Reduce rate by 50%
		} else if errorRate < 0.01 { // Less than 1% error rate
			baseRate = baseRate * 1.5 // Increase rate by 50%
		}
	}

	// Adjust based on response times
	if times, exists := irl.responseTimes[host]; exists && len(times) > 5 {
		avgResponse := irl.calculateAverageResponse(times)
		if avgResponse > 5*time.Second {
			baseRate = baseRate * 0.7 // Slow responses, reduce rate
		} else if avgResponse < 1*time.Second {
			baseRate = baseRate * 1.2 // Fast responses, increase rate
		}
	}

	// Ensure rate doesn't exceed reasonable bounds
	maxRate := rate.Limit(60.0 / 60.0) // 60 requests per minute max
	minRate := rate.Limit(1.0 / 60.0)  // 1 request per minute min

	if baseRate > maxRate {
		baseRate = maxRate
	} else if baseRate < minRate {
		baseRate = minRate
	}

	return baseRate
}

// getCircuitBreaker gets or creates a circuit breaker for a host
func (irl *IntelligentRateLimiter) getCircuitBreaker(host string) *CircuitBreaker {
	irl.circuitMutex.RLock()
	breaker, exists := irl.circuitBreakers[host]
	irl.circuitMutex.RUnlock()

	if !exists {
		irl.circuitMutex.Lock()
		breaker = &CircuitBreaker{
			state:     CircuitClosed,
			threshold: irl.circuitThreshold,
			timeout:   2 * time.Minute, // 2 minute timeout before trying half-open
		}
		irl.circuitBreakers[host] = breaker
		irl.circuitMutex.Unlock()
	}

	return breaker
}

// Circuit breaker methods
func (cb *CircuitBreaker) canProceed() bool {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	switch cb.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		if time.Since(cb.lastFailureTime) > cb.timeout {
			cb.state = CircuitHalfOpen
			return true
		}
		return false
	case CircuitHalfOpen:
		return true
	}
	return false
}

func (cb *CircuitBreaker) recordSuccess() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.failureCount = 0
	if cb.state == CircuitHalfOpen {
		cb.state = CircuitClosed
	}
}

func (cb *CircuitBreaker) recordFailure() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.failureCount++
	cb.lastFailureTime = time.Now()

	if cb.state == CircuitHalfOpen {
		cb.state = CircuitOpen
	}
}

func (cb *CircuitBreaker) shouldTrip() bool {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	if cb.state == CircuitClosed && cb.failureCount >= cb.threshold {
		cb.state = CircuitOpen
		return true
	}
	return false
}

func (cb *CircuitBreaker) getWaitTime() time.Duration {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	if cb.state == CircuitOpen {
		return cb.timeout - time.Since(cb.lastFailureTime)
	}
	return 0
}

// updateErrorRate updates the error rate for a host
func (irl *IntelligentRateLimiter) updateErrorRate(host string, success bool) {
	const windowSize = 100 // Track last 100 requests

	errorRate := irl.errorRates[host]

	// Simple exponential moving average
	alpha := 0.1 // Smoothing factor
	if success {
		errorRate = errorRate*(1-alpha) + 0*alpha
	} else {
		errorRate = errorRate*(1-alpha) + 1*alpha
	}

	irl.errorRates[host] = errorRate
}

// adaptRateLimit adapts the rate limit for a host based on performance metrics
func (irl *IntelligentRateLimiter) adaptRateLimit(host string) {
	// Get current host limiter
	irl.hostMutex.Lock()
	limiter, exists := irl.hostLimiters[host]
	if exists {
		// Update limiter with new adaptive rate
		newRate := irl.calculateAdaptiveRate(host)
		limiter.SetLimit(newRate)
	}
	irl.hostMutex.Unlock()
}

// applyBackoff applies exponential backoff for a host
func (irl *IntelligentRateLimiter) applyBackoff(host string) {
	irl.adaptiveMutex.Lock()
	defer irl.adaptiveMutex.Unlock()

	currentBackoff, exists := irl.backoffPeriods[host]
	if !exists {
		// First backoff: 30 seconds
		irl.backoffPeriods[host] = time.Now().Add(30 * time.Second)
	} else {
		// Exponential backoff
		remainingTime := time.Until(currentBackoff)
		if remainingTime <= 0 {
			remainingTime = 30 * time.Second
		}

		newBackoff := time.Duration(float64(remainingTime) * irl.backoffMultiplier)
		if newBackoff > irl.maxBackoff {
			newBackoff = irl.maxBackoff
		}

		irl.backoffPeriods[host] = time.Now().Add(newBackoff)
	}

	log.Printf("[RATE_LIMITER] Applied backoff for host %s until %v",
		host, irl.backoffPeriods[host])
}

// getBackoffPeriod gets the backoff period for a host
func (irl *IntelligentRateLimiter) getBackoffPeriod(host string) time.Time {
	irl.adaptiveMutex.RLock()
	defer irl.adaptiveMutex.RUnlock()
	return irl.backoffPeriods[host]
}

// clearBackoffPeriod clears the backoff period for a host
func (irl *IntelligentRateLimiter) clearBackoffPeriod(host string) {
	irl.adaptiveMutex.Lock()
	defer irl.adaptiveMutex.Unlock()
	delete(irl.backoffPeriods, host)
}

// calculateAverageResponse calculates average response time
func (irl *IntelligentRateLimiter) calculateAverageResponse(times []time.Duration) time.Duration {
	if len(times) == 0 {
		return 0
	}

	var total time.Duration
	for _, t := range times {
		total += t
	}
	return total / time.Duration(len(times))
}

// Metrics methods
func (irl *IntelligentRateLimiter) incrementTotalRequests() {
	irl.metricsMutex.Lock()
	defer irl.metricsMutex.Unlock()
	irl.totalRequests++
}

func (irl *IntelligentRateLimiter) incrementBlockedRequests() {
	irl.metricsMutex.Lock()
	defer irl.metricsMutex.Unlock()
	irl.blockedRequests++
}

func (irl *IntelligentRateLimiter) incrementCircuitTrips() {
	irl.metricsMutex.Lock()
	defer irl.metricsMutex.Unlock()
	irl.circuitTrips++
}

// GetStats returns rate limiting statistics for a host
func (irl *IntelligentRateLimiter) GetStats(host string) *RateLimitStats {
	irl.adaptiveMutex.RLock()
	irl.circuitMutex.RLock()
	defer irl.adaptiveMutex.RUnlock()
	defer irl.circuitMutex.RUnlock()

	stats := &RateLimitStats{
		Host:        host,
		LastUpdated: time.Now(),
	}

	// Get response time stats
	if times, exists := irl.responseTimes[host]; exists {
		stats.AverageResponse = irl.calculateAverageResponse(times)
	}

	// Get error rate
	if errorRate, exists := irl.errorRates[host]; exists {
		stats.ErrorRate = errorRate
	}

	// Get circuit breaker state
	if breaker, exists := irl.circuitBreakers[host]; exists {
		breaker.mutex.RLock()
		switch breaker.state {
		case CircuitClosed:
			stats.CircuitState = "closed"
		case CircuitOpen:
			stats.CircuitState = "open"
		case CircuitHalfOpen:
			stats.CircuitState = "half_open"
		}
		breaker.mutex.RUnlock()
	}

	// Get backoff information
	if backoffEnd, exists := irl.backoffPeriods[host]; exists {
		if time.Now().Before(backoffEnd) {
			stats.BackoffUntil = &backoffEnd
		}
	}

	return stats
}

// GetGlobalStats returns global rate limiting statistics
func (irl *IntelligentRateLimiter) GetGlobalStats() map[string]interface{} {
	irl.metricsMutex.RLock()
	defer irl.metricsMutex.RUnlock()

	uptime := time.Since(irl.metricsStartTime)

	return map[string]interface{}{
		"total_requests":      irl.totalRequests,
		"blocked_requests":    irl.blockedRequests,
		"circuit_trips":       irl.circuitTrips,
		"uptime_seconds":      uptime.Seconds(),
		"requests_per_second": float64(irl.totalRequests) / uptime.Seconds(),
		"block_rate":          float64(irl.blockedRequests) / float64(irl.totalRequests),
	}
}

// storeMetrics stores rate limiting metrics in the database
func (irl *IntelligentRateLimiter) storeMetrics(host string) {
	stats := irl.GetStats(host)

	query := `
		INSERT INTO rate_limiter_stats (host, requests_allowed, requests_blocked, average_response, error_rate, circuit_state, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (host) DO UPDATE SET
			requests_allowed = EXCLUDED.requests_allowed,
			requests_blocked = EXCLUDED.requests_blocked,
			average_response = EXCLUDED.average_response,
			error_rate = EXCLUDED.error_rate,
			circuit_state = EXCLUDED.circuit_state,
			updated_at = EXCLUDED.updated_at
	`

	_, err := irl.dbPool.Exec(context.Background(), query,
		stats.Host, stats.RequestsAllowed, stats.RequestsBlocked,
		stats.AverageResponse.Milliseconds(), stats.ErrorRate, stats.CircuitState)

	if err != nil {
		log.Printf("[RATE_LIMITER] Failed to store metrics for host %s: %v", host, err)
	}
}

// Reset resets all rate limiting state (useful for testing)
func (irl *IntelligentRateLimiter) Reset() {
	irl.hostMutex.Lock()
	irl.adaptiveMutex.Lock()
	irl.circuitMutex.Lock()
	irl.metricsMutex.Lock()
	defer irl.hostMutex.Unlock()
	defer irl.adaptiveMutex.Unlock()
	defer irl.circuitMutex.Unlock()
	defer irl.metricsMutex.Unlock()

	// Reset all maps
	irl.hostLimiters = make(map[string]*rate.Limiter)
	irl.responseTimes = make(map[string][]time.Duration)
	irl.errorRates = make(map[string]float64)
	irl.backoffPeriods = make(map[string]time.Time)
	irl.circuitBreakers = make(map[string]*CircuitBreaker)

	// Reset metrics
	irl.totalRequests = 0
	irl.blockedRequests = 0
	irl.circuitTrips = 0
	irl.metricsStartTime = time.Now()

	log.Printf("[RATE_LIMITER] Rate limiter state reset")
}
