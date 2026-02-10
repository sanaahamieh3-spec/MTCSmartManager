-- =====================================================
-- SECURITY ENGINEERING MODULE
-- Author: Security Engineer
-- Purpose: Monitoring, Auditing, Automation & Defense
-- =====================================================

-- ================================
-- SECURITY LOGS (AUDIT TRAIL)
-- ================================
CREATE TABLE security_logs (
    log_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    event_type ENUM(
        'login_success',
        'login_failed',
        'suspicious_activity',
        'unauthorized_access',
        'account_locked',
        'account_unlocked',
        'session_expired',
        'large_transaction'
    ) NOT NULL,
    ip_address VARCHAR(45),
    device_id VARCHAR(255),
    user_agent TEXT,
    risk_score INT CHECK (risk_score BETWEEN 0 AND 100),
    event_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_details TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_risk_time (risk_score, event_timestamp)
);

-- ================================
-- SECURITY ALERTS (USER NOTIFICATION)
-- ================================
CREATE TABLE security_alerts (
    alert_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    alert_type ENUM(
        'failed_login',
        'suspicious_activity',
        'account_locked',
        'large_transaction',
        'new_device_detected'
    ) NOT NULL,
    alert_message TEXT NOT NULL,
    severity ENUM('info','warning','critical') DEFAULT 'info',
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    read_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_alerts_user (user_id, is_read)
);

-- ================================
-- ENCRYPTION KEY MANAGEMENT
-- ================================
CREATE TABLE encryption_keys (
    key_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    key_hash VARCHAR(512) NOT NULL,      -- encrypted key (AES/RSA wrapped)
    key_algorithm ENUM('AES-256','RSA-2048') DEFAULT 'AES-256',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    rotated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- ================================
-- VIEW: HIGH-RISK EVENTS DASHBOARD
-- ================================
CREATE VIEW high_risk_events AS
SELECT
    sl.log_id,
    u.full_name,
    u.phone_number,
    sl.event_type,
    sl.risk_score,
    sl.ip_address,
    sl.event_timestamp
FROM security_logs sl
JOIN users u ON sl.user_id = u.user_id
WHERE sl.risk_score >= 70
ORDER BY sl.event_timestamp DESC;

-- ================================
-- PROCEDURE: AUTO-UNLOCK EXPIRED ACCOUNTS
-- ================================
DELIMITER $$

CREATE PROCEDURE unlock_expired_accounts()
BEGIN
    UPDATE users
    SET account_status = 'active',
        failed_login_attempts = 0,
        locked_until = NULL
    WHERE account_status = 'locked'
      AND locked_until IS NOT NULL
      AND locked_until <= NOW();

    -- Log automated recovery
    INSERT INTO security_logs (user_id, event_type, risk_score, event_details)
    SELECT user_id, 'account_unlocked', 10, 'Account auto-unlocked by scheduler'
    FROM users
    WHERE account_status = 'active'
      AND locked_until IS NULL;
END$$
DELIMITER ;

-- ================================
-- PROCEDURE: EXPIRE SUSPICIOUS SESSIONS
-- ================================
DELIMITER $$

CREATE PROCEDURE expire_suspicious_sessions()
BEGIN
    UPDATE sessions
    SET is_active = FALSE
    WHERE expires_at <= NOW()
       OR session_id IN (
           SELECT DISTINCT device_id
           FROM security_logs
           WHERE risk_score >= 80
       );
END$$
DELIMITER ;

-- ================================
-- TRIGGER: ALERT ON CRITICAL RISK
-- ================================
DELIMITER $$

CREATE TRIGGER alert_on_critical_risk
AFTER INSERT ON security_logs
FOR EACH ROW
BEGIN
    IF NEW.risk_score >= 85 THEN
        INSERT INTO security_alerts (
            user_id,
            alert_type,
            alert_message,
            severity
        )
        VALUES (
            NEW.user_id,
            'suspicious_activity',
            CONCAT('High-risk activity detected from IP ', NEW.ip_address),
            'critical'
        );
    END IF;
END$$
DELIMITER ;

-- ================================
-- SCHEDULED SECURITY AUTOMATION
-- ================================

SET GLOBAL event_scheduler = ON;

-- Auto-unlock accounts every minute
CREATE EVENT ev_unlock_accounts
ON SCHEDULE EVERY 1 MINUTE
DO CALL unlock_expired_accounts();

-- Expire suspicious sessions every 5 minutes
CREATE EVENT ev_expire_sessions
ON SCHEDULE EVERY 5 MINUTE
DO CALL expire_suspicious_sessions();

-- Log retention: keep 90 days
CREATE EVENT ev_cleanup_security_logs
ON SCHEDULE EVERY 1 DAY
DO
    DELETE FROM security_logs
    WHERE event_timestamp < DATE_SUB(NOW(), INTERVAL 90 DAY);
