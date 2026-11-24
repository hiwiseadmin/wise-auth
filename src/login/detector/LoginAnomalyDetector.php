<?php
declare(strict_types=1);

namespace wise\login\detector;

use think\facade\Cache;
use wise\support\context\ContextualLogger;
use wise\login\model\UserDevice;
use wise\login\model\SecurityEvent;
use wise\support\rate\RateLimiter;

/**
 * 登录异常检测引擎＼�
 *
 * 在登录成功后检测异常行为，触发安全事件提醒。
 *
 * 四类检测规则（均可独立开关）：
 *  1. 异地登录：同账号 N 分钟内从不同 IP 登录
 *  2. 新设备+新IP：新设备指纹且 IP 不在历史记录中
 *  3. 异常时段：凌晨 1:00-5:00 登录
 *  4. 频率异常：短时间内登录次数超过阈值
 *
 * 配置：config('wise-auth.login.anomaly_detection')
 *
 * 用法（在 LoginResultMiddleware::handleSuccess 中调用）：
 *   $detector = app(LoginAnomalyDetector::class);
 *   $anomalies = $detector->detect($userId, $username, $ip, $ua);
 *   foreach ($anomalies as $anomaly) { ... }
 */
class LoginAnomalyDetector
{
    protected array $config;
    protected string $cachePrefix;

    public function __construct()
    {
        $this->config = (array) config('wise-auth.login.anomaly_detection', []);
        $this->cachePrefix = $this->config['cache_prefix'] ?? 'wise_login_security:anomaly:';
    }

    /**
     * 执行所有检测规则，返回异常列表
     *
     * @param int         $userId   用户 ID
     * @param string      $username 用户名
     * @param string      $ip       登录 IP
     * @param string      $ua       User-Agent
     * @param string|null $fingerprint 设备指纹（可选）
     * @return AnomalyResult[] 异常结果列表
     */
    public function detect(int $userId, string $username, string $ip, string $ua, ?string $fingerprint = null): array
    {
        if (!($this->config['enabled'] ?? true)) {
            return [];
        }

        $results = [];

        if ($this->config['geo_anomaly']['enabled'] ?? true) {
            $anomaly = $this->detectGeoAnomaly($userId, $username, $ip, $ua);
            if ($anomaly !== null) {
                $results[] = $anomaly;
            }
        }

        if ($this->config['new_device']['enabled'] ?? true) {
            $anomaly = $this->detectNewDeviceAnomaly($userId, $username, $ip, $fingerprint ?? $this->buildFingerprint($ua, $ip));
            if ($anomaly !== null) {
                $results[] = $anomaly;
            }
        }

        if ($this->config['time_anomaly']['enabled'] ?? true) {
            $anomaly = $this->detectTimeAnomaly($username, $ip);
            if ($anomaly !== null) {
                $results[] = $anomaly;
            }
        }

        if ($this->config['frequency_anomaly']['enabled'] ?? true) {
            $anomaly = $this->detectFrequencyAnomaly($userId, $username, $ip);
            if ($anomaly !== null) {
                $results[] = $anomaly;
            }
        }

        $this->recordLogin($userId, $ip, $fingerprint ?? '');

        return $results;
    }

    /**
     * 规则1：异地登录检测
     *
     * 检查同一账号在 N 分钟内是否从不同 IP 登录
     */
    protected function detectGeoAnomaly(int $userId, string $username, string $ip, string $ua): ?AnomalyResult
    {
        $cfg = $this->config['geo_anomaly'] ?? [];
        $windowMinutes = (int) ($cfg['window_minutes'] ?? 60);
        $threshold = (int) ($cfg['ip_count_threshold'] ?? 2);

        $key    = $this->cachePrefix . 'geo:' . $userId;
        $window = $windowMinutes * 60;
        $cutoff = time() - $window;

        $history = Cache::get($key, []);

        $history[] = ['ip' => $ip, 'time' => time()];

        $history = array_values(array_filter($history, fn($r) => $r['time'] >= $cutoff));

        $ips = array_unique(array_column($history, 'ip'));
        try {
            $handler = Cache::store('redis')->handler();
            if ($handler instanceof \Redis) {
                $handler->sAdd($key . ':ips', $ip);
                $handler->expire($key . ':ips', $window);
                $ips = (array) $handler->sMembers($key . ':ips');
            }
        } catch (\Throwable) {
        }
        $ips = array_values(array_unique(array_map('strval', $ips)));

        Cache::set($key, $history, $window);

        if (count($ips) >= $threshold) {
            return new AnomalyResult(
                type: 'geo_anomaly',
                severity: AnomalyResult::SEVERITY_HIGH,
                message: sprintf('账号 %s 在 %d 分钟内从 %d 个不同 IP 登录', $username, $windowMinutes, count($ips)),
                data: ['ips' => array_values($ips), 'history' => $history]
            );
        }

        return null;
    }

    /**
     * 规则2：新设备+新IP 检测
     *
     * 检查设备指纹和 IP 是否都在历史记录中不存在
     */
    protected function detectNewDeviceAnomaly(int $userId, string $username, string $ip, string $fingerprint): ?AnomalyResult
    {
        $cfg = $this->config['new_device'] ?? [];
        $lookbackDays = (int) ($cfg['lookback_days'] ?? 7);

        $deviceExists = UserDevice::where('user_id', $userId)
            ->where('device_fingerprint', $fingerprint)
            ->find();

        $ipUsed = $this->isIpUsedBefore($userId, $ip, $lookbackDays);

        if (!$deviceExists && !$ipUsed) {
            return new AnomalyResult(
                type: 'new_device_ip',
                severity: AnomalyResult::SEVERITY_MEDIUM,
                message: sprintf('账号 %s 使用全新设备和 IP 登录', $username),
                data: ['ip' => $ip, 'fingerprint' => $fingerprint]
            );
        }

        return null;
    }

    /**
     * 规则3：异常时段检测
     *
     * 检查登录时间是否在设定的异常时段内（默认凌晨 1:00-5:00）
     */
    protected function detectTimeAnomaly(string $username, string $ip): ?AnomalyResult
    {
        $cfg = $this->config['time_anomaly'] ?? [];
        $startHour = (int) ($cfg['start_hour'] ?? 1);
        $endHour = (int) ($cfg['end_hour'] ?? 5);

        $hour = (int) date('G');

        $isAnomalyHour = $startHour <= $endHour
            ? ($hour >= $startHour && $hour <= $endHour)
            : ($hour >= $startHour || $hour <= $endHour);

        if ($isAnomalyHour) {
            return new AnomalyResult(
                type: 'time_anomaly',
                severity: AnomalyResult::SEVERITY_LOW,
                message: sprintf('账号 %s 在异常时段（%02d:00-%02d:00）登录', $username, $startHour, $endHour),
                data: ['ip' => $ip, 'hour' => $hour]
            );
        }

        return null;
    }

    /**
     * 规则4：频率异常检测
     *
     * 检查短时间内登录次数是否超过阈值
     */
    protected function detectFrequencyAnomaly(int $userId, string $username, string $ip): ?AnomalyResult
    {
        $cfg = $this->config['frequency_anomaly'] ?? [];
        $windowMinutes = (int) ($cfg['window_minutes'] ?? 10);
        $threshold = (int) ($cfg['login_threshold'] ?? 5);

        $limiter = RateLimiter::perMinutes($threshold, $windowMinutes)
            ->withPrefix(rtrim($this->cachePrefix, ':'))
            ->by('freq:' . $userId);

        $remaining = $limiter->hit();
        $count = $threshold - $remaining;

        if ($count >= $threshold) {
            return new AnomalyResult(
                type: 'frequency_anomaly',
                severity: AnomalyResult::SEVERITY_MEDIUM,
                message: sprintf('账号 %s 在 %d 分钟内登录 %d 次', $username, $windowMinutes, $count),
                data: ['count' => $count, 'window_minutes' => $windowMinutes]
            );
        }

        return null;
    }

    /**
     * 检查 IP 是否在历史中被该用户使用过
     */
    protected function isIpUsedBefore(int $userId, string $ip, int $lookbackDays): bool
    {
        $since = date('Y-m-d H:i:s', time() - $lookbackDays * 86400);

        $count = SecurityEvent::where('event_type', 'login_success')
            ->where('ip', $ip)
            ->where('create_time', '>=', $since)
            ->where(function ($query) use ($userId) {
                $query->where('details', 'like', '%"user_id":' . $userId . ',%')
                    ->whereOr('details', 'like', '%"user_id":' . $userId . '}%')
                    ->whereOr('details', 'like', '%"user_id":' . $userId);
            })
            ->count();

        return $count > 0;
    }

    /**
     * 记录当前登录信息
     */
    protected function recordLogin(int $userId, string $ip, string $fingerprint): void
    {
        $key = $this->cachePrefix . 'last_login:' . $userId;
        Cache::set($key, [
            'ip'          => $ip,
            'fingerprint' => $fingerprint,
            'time'        => time(),
        ], 86400 * 30);
    }

    /**
     * 构建设备指纹（简化版）
     */
    protected function buildFingerprint(string $ua, string $ip): string
    {
        return hash('sha256', $ua);
    }
}
