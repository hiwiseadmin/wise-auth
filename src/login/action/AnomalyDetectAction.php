<?php
declare(strict_types=1);

namespace wise\login\action;

use Closure;
use wise\login\contract\LoginResultAction;
use wise\login\contract\LoginResultPayload;
use wise\login\detector\LoginAnomalyDetector;
use wise\login\facade\Logger;
use wise\login\ip\CidrMatcher;

/**
 * 登录异常检测 Action
 *
 * 登录成功后执行异常检测规则（异地/IP/时间/频率），
 * 检测到的异常通过 Logger::log 记录。
 *
 * 从 LoginResultMiddleware::detectAnomalies() 提取
 */
class AnomalyDetectAction implements LoginResultAction
{
    /**
     * 执行登录异常检测（异地/IP/时间/频率），异常不影响登录但记录日志
     *
     * @param LoginResultPayload $payload
     * @param Closure            $next
     * @return LoginResultPayload
     */
    public function handle(LoginResultPayload $payload, Closure $next): LoginResultPayload
    {
        if (!$payload->isSuccess || !$payload->userId) {
            return $next($payload);
        }

        if (!$payload->actionEnabled('anomaly_detect')) {
            return $next($payload);
        }

        try {
            $detector  = app(LoginAnomalyDetector::class);
            $request   = $payload->request;
            $anomalies = $detector->detect(
                (int) $payload->userId,
                $payload->username ?? 'unknown',
                CidrMatcher::fromRequest($request),
                $request->header('User-Agent', ''),
                null
            );

            foreach ($anomalies as $anomaly) {
                Logger::log('anomaly_detected', [
                    'anomaly_type'     => $anomaly->type,
                    'anomaly_severity' => $anomaly->severity,
                    'anomaly_message'  => $anomaly->message,
                    'anomaly_data'     => $anomaly->data,
                    'user_id'          => $payload->userId,
                    'username'         => $payload->username,
                ], $request, $payload->username);
            }
        } catch (\Throwable $e) {
            Logger::log('anomaly_detect_error', [
                'error'    => $e->getMessage(),
                'user_id'  => $payload->userId,
                'username' => $payload->username,
            ], $payload->request, $payload->username);
        }

        return $next($payload);
    }
}
