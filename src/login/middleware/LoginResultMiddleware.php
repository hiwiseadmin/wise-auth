<?php
declare(strict_types=1);

namespace wise\login\middleware;


use wise\support\context\ContextualLogger;
use think\facade\Config;
use think\helper\Arr;
use think\Request;
use think\Response;
use wise\login\action\AnomalyDetectAction;
use wise\login\action\DeviceRecordAction;
use wise\login\action\FailureRecordAction;
use wise\login\action\SuccessRecordAction;
use wise\login\contract\LoginResultPayload;
use wise\login\LoginPipeline;
use wise\login\LoginRegistry;

/**
 * 登录结果后置中间件（V2: Pipeline 架构）
 *
 * 将原来的硬编码成功/失败处理拆分为可编排的 Action 管道。
 * 插件可通过 LoginRegistry::registerResultAction() 插入自定义处理步骤。
 *
 * 自动完成以下动作（均可单独开关）：
 *   - 失败 → Lock::recordFailure() + Logger::log(LOGIN_FAILURE) + 锁定邮件通知
 *   - 成功 → Lock::clear() + Logger::log(LOGIN_SUCCESS) + DeviceManager::record()
 *          + TwoFactorMiddleware::markVerified() + LoginAnomalyDetector::detect()
 *
 * 用法：
 *   Route::post('login', 'Auth/login')->middleware([LoginResultMiddleware::class]);
 */
class LoginResultMiddleware
{
    public function handle(Request $request, \Closure $next): Response
    {
        $response = $next($request);

        try {
            $this->process($request, $response);
        } catch (\Throwable $e) {
            ContextualLogger::error('[LoginResultMiddleware] ' . $e->getMessage(), [
                'exception' => $e::class,
                'trace'     => $e->getTraceAsString(),
            ]);
        }

        return $response;
    }

    protected function process(Request $request, Response $response): void
    {
        $cfg = $this->config();
        if (!($cfg['enabled'] ?? true)) {
            return;
        }

        $content = $response->getContent();
        if (empty($content)) {
            return;
        }

        $body = json_decode($content, true);
        if (!is_array($body)) {
            return;
        }

        $statusField  = $cfg['response']['status_field'] ?? 'code';
        $successValue = $cfg['response']['success_value'] ?? 0;

        if (!array_key_exists($statusField, $body)) {
            return;
        }

        $status    = $body[$statusField];
        $isSuccess = ((string) $status === (string) $successValue);

        $username = $this->getUsername($request, $cfg);
        $userId   = $isSuccess ? $this->getUserId($body, $cfg, $request) : null;

        $payload = new LoginResultPayload($request, $response, $body, $isSuccess, $cfg);
        $payload->username = $username;
        $payload->userId   = $userId;

        $pipeline = new LoginPipeline();
        $pipeline
            ->through($this->resolveResultActions($payload))
            ->resultThen($payload, function (LoginResultPayload $p) {
                return $p;
            });
    }

    /**
     * 解析结果 Action 列表（配置 + 插件注册）
     */
    protected function resolveResultActions(LoginResultPayload $payload): array
    {
        $actions = [];

        if ($payload->actionEnabled('failure_lock') || $payload->actionEnabled('failure_event') || $payload->actionEnabled('lock_notify')) {
            $actions[] = new FailureRecordAction();
        }

        if ($payload->actionEnabled('success_clear') || $payload->actionEnabled('success_event')) {
            $actions[] = new SuccessRecordAction();
        }

        if ($payload->actionEnabled('device_record') || $payload->actionEnabled('totp_verified')) {
            $actions[] = new DeviceRecordAction();
        }

        if ($payload->actionEnabled('anomaly_detect')) {
            $actions[] = new AnomalyDetectAction();
        }

        $pluginActions = LoginRegistry::getResultActions();
        foreach ($pluginActions as $action) {
            $actions[] = is_string($action) ? app()->make($action) : $action;
        }

        return $actions;
    }

    protected function getUsername(Request $request, array $cfg): ?string
    {
        $field = $cfg['username_input'] ?? 'username';
        return $request->param($field);
    }

    protected function getUserId(array $body, array $cfg, Request $request): ?int
    {
        $field = $cfg['response']['user_id_field'] ?? 'data.user_id';

        if (is_array($field) || $field instanceof \Closure) {
            $value = call_user_func($field, $body, $request);
            return $value !== null ? (int) $value : null;
        }

        $value = Arr::get($body, $field);
        return $value !== null ? (int) $value : null;
    }

    protected function config(): array
    {
        $defaults = [
            'enabled' => true,
            'response' => [
                'status_field'  => 'code',
                'success_value' => 0,
                'user_id_field' => 'data.user_id',
            ],
            'username_input' => 'username',
            'actions' => [
                'failure_lock'   => true,
                'failure_event'  => true,
                'lock_notify'    => true,
                'success_clear'  => true,
                'success_event'  => true,
                'device_record'  => true,
                'totp_verified'  => true,
                'anomaly_detect' => true,
            ],
        ];

        $userConfig = Config::get('wise-auth.login.login_result', []);
        return array_replace_recursive($defaults, $userConfig);
    }
}
