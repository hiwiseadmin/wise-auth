<?php
declare(strict_types=1);

namespace wise\login\event;

use think\App;
use wise\support\context\ContextualLogger;
use think\Request;
use wise\login\ip\CidrMatcher;
use wise\login\model\SecurityEvent;

/**
 * 事件记录器
 *
 * - 写数据库（按配置）
 * - 写日志文件（按配置）
 * - 触发 PSR-14 事件（始终）
 */
class EventLogger
{
    public function __construct(protected App $app)
    {
    }

    /**
     * 记录一条安全事件
     *
     * @param string     $type    LoginEvent::TYPE_*
     * @param array      $data
     * @param Request|null $request
     * @param string|null $username
     */
    public function log(string $type, array $data = [], ?Request $request = null, ?string $username = null): void
    {
        $username = $username ?? ($data['username'] ?? null);
        $ip = $request ? CidrMatcher::fromRequest($request) : ($data['ip'] ?? null);
        $userAgent = $this->resolveUserAgent($request, $data);

        $logToDb = (bool) (config('wise-auth.login.events.log_to_database', true));
        if ($logToDb) {
            try {
                SecurityEvent::create([
                    'event_type' => $type,
                    'username'   => $username,
                    'ip'         => $ip,
                    'user_agent' => $userAgent !== null ? mb_substr($userAgent, 0, 500) : null,
                    'details'    => json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
                    'create_time' => date('Y-m-d H:i:s'),
                ]);
            } catch (\Throwable $e) {
                if ((bool) config('wise-auth.login.events.log_to_file', true)) {
                    ContextualLogger::channel(config('wise-auth.login.events.log_channel', 'file'))
                        ->warning('[login-security] DB log failed: ' . $e->getMessage());
                }
            }
        }

        try {
            $logToFile = (bool) (config('wise-auth.login.events.log_to_file', true));
            if ($logToFile) {
                $jsonData = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
                ContextualLogger::channel(config('wise-auth.login.events.log_channel', 'file'))
                    ->info("[{$type}] user={$username} ip={$ip} data=" . $jsonData);
            }
        } catch (\Throwable $e) {
        }

        try {
            $this->app->event->trigger(
                new LoginEvent($type, $data, $username, $ip, $userAgent)
            );
        } catch (\Throwable $e) {
            $logToFile = (bool) (config('wise-auth.login.events.log_to_file', true));
            if ($logToFile) {
                try {
                    ContextualLogger::channel(config('wise-auth.login.events.log_channel', 'file'))
                        ->warning('[login-security] Event dispatch failed: ' . $e->getMessage());
                } catch (\Throwable) {
                }
            }
        }
    }

    /**
     * 多途径解析 User-Agent（与 app\common\library\Client::getUserAgent() 保持一致的回退策略）
     *
     * 实测：同一登录请求中，$request->header('user-agent') 可能取不到，
     * 而 $_SERVER['HTTP_USER_AGENT'] 可靠。故依次回退：
     *   request->header() → request->server('HTTP_USER_AGENT') → $data['user_agent'] → $_SERVER
     */
    protected function resolveUserAgent(?Request $request, array $data): ?string
    {
        if ($request) {
            $ua = (string) $request->header('user-agent');
            if ($ua !== '') {
                return $ua;
            }
            $ua = (string) $request->server('HTTP_USER_AGENT');
            if ($ua !== '') {
                return $ua;
            }
        }
        if (!empty($data['user_agent'])) {
            return (string) $data['user_agent'];
        }

        return null;
    }
}
