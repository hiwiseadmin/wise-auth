<?php
declare(strict_types=1);

namespace wise\login;

/**
 * 登录安全注册表（Login Security Registry）
 *
 * V2: 插件 Action 注册中心。
 * 插件可通过此注册表插入自定义的登录守卫和结果处理 Action。
 *
 * 使用示例：
 * <pre>
 * // 注册自定义守卫检查（如 Sla 状态检查）
 * LoginRegistry::registerGuard(\plugin\custom\actions\SlaCheckAction::class);
 *
 * // 注册自定义结果处理（如同步登录状态到第三方）
 * LoginRegistry::registerResultAction(\plugin\custom\actions\SyncLoginAction::class);
 * </pre>
 *
 * @package wise\login
 */
class LoginRegistry
{
    /**
     * 插件注册的守卫 Action 列表
     * @var array<string|object>
     */
    protected static $guardActions = [];

    /**
     * 插件注册的结果 Action 列表
     * @var array<string|object>
     */
    protected static $resultActions = [];

    /**
     * 注册自定义登录守卫 Action
     *
     * 守卫 Action 在标准的 IP → 锁定 → 验证码 检查之后执行。
     * 实现 LoginGuardAction 接口。
     *
     * @param string|object $action Action 类名或实例
     */
    public static function registerGuard($action): void
    {
        if (static::contains(static::$guardActions, $action)) {
            return;
        }
        static::$guardActions[] = $action;
    }

    /**
     * 注册自定义登录结果 Action
     *
     * 结果 Action 在标准的结果处理链末尾执行。
     * 实现 LoginResultAction 接口。
     *
     * @param string|object $action Action 类名或实例
     */
    public static function registerResultAction($action): void
    {
        if (static::contains(static::$resultActions, $action)) {
            return;
        }
        static::$resultActions[] = $action;
    }

    /**
     * 判断注册表中是否已存在同一 Action（兼容类名字符串与对象实例两种形态）
     *
     * @param array         $list   已有注册项
     * @param string|object $action 待注册项
     */
    protected static function contains(array $list, $action): bool
    {
        $key = is_string($action) ? $action : get_class($action);

        foreach ($list as $registered) {
            if ((is_string($registered) ? $registered : get_class($registered)) === $key) {
                return true;
            }
        }

        return false;
    }

    /**
     * 获取所有插件注册的守卫 Action
     *
     * @return array
     */
    public static function getGuardActions(): array
    {
        return static::$guardActions;
    }

    /**
     * 获取所有插件注册的结果 Action
     *
     * @return array
     */
    public static function getResultActions(): array
    {
        return static::$resultActions;
    }

    /**
     * 清除所有插件注册（用于测试）
     */
    public static function clear(): void
    {
        static::$guardActions  = [];
        static::$resultActions = [];
    }
}
