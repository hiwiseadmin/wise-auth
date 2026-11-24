<?php

declare(strict_types=1);

namespace wise\login;

use think\facade\Route;
use wise\support\router\RouteRegistrar as BaseRouteRegistrar;

/**
 * 登录安全路由注册器（配置驱动）
 *
 * 由 LoginServiceProvider::boot() 调用 RouteRegistrar::register() 注册。
 * 前缀 / 中间件 / 限流通过 config('wise-auth.login.web') 配置。
 *
 * 兼容旧配置：未设置 web.prefix 时，回退读取 route.prefix（默认 wise/captcha）。
 *
 * @package wise\login
 */
class RouteRegistrar extends BaseRouteRegistrar
{
    protected string $configKey = 'wise-auth.login';

    /**
     * 读取 web 配置节，兼容旧版 route.prefix
     */
    protected function webConfig(): array
    {
        $config = parent::webConfig();
        if (empty($config['prefix'])) {
            $oldPrefix = config('wise-auth.login.route.prefix', 'wise/captcha');
            $config['prefix'] = $oldPrefix ?: 'wise/captcha';
        }
        return $config;
    }

    protected function define(array $config): void
    {
        $this->group('captcha', function () {
            Route::get('create', '\wise\login\controller\CaptchaController@create');

            Route::post('verify', '\wise\login\controller\CaptchaController@verify');

            Route::get('image', '\wise\login\controller\CaptchaController@image');
        });

        $this->registerAdminRoutes();
    }

    /**
     * 后台「安全管理」页面路由（/admin/login_security_*）
     *
     * 分组前缀 'admin'（见 config 的 web.groups.admin_security），由基类投递到
     * ROUTE_ADMIN，在 admin 应用内以相对前缀 '' 落地，与菜单声明
     * （{@see \wise\login\menu\LoginMenuProvider}）一一对应，
     * 卸载本包后路由与菜单一并消失，宿主不再硬编码。
     *
     * 依赖 WiseAdmin 宿主提供的 admin 控制器基类（复用后台视图壳与响应 helper）；
     * 脱离该宿主时跳过注册，避免路由命中后 500。
     *
     * 注册方式说明：使用 {@see Route::rule()}（默认匹配全部请求方法）等价于迁移前
     * 后台默认调度（module/controller/action）的方法无关行为，避免前端既有
     * GET/POST 调用方式差异造成 405 回归；鉴权仍由 admin 应用级 RBAC 中间件统一负责。
     */
    protected function registerAdminRoutes(): void
    {
        if (!class_exists(\app\admin\controller\BaseController::class)) {
            return;
        }

        $this->group('admin_security', function () {
            Route::rule('auth/login/attempt/index', '\wise\login\controller\LoginAttempt@index');
            Route::rule('auth/login/attempt/getList', '\wise\login\controller\LoginAttempt@getList');
            Route::rule('auth/login/attempt/unlock', '\wise\login\controller\LoginAttempt@unlock');
            Route::rule('auth/login/attempt/clearExpired', '\wise\login\controller\LoginAttempt@clearExpired');

            Route::rule('auth/login/device/index', '\wise\login\controller\LoginDevice@index');
            Route::rule('auth/login/device/getList', '\wise\login\controller\LoginDevice@getList');
            Route::rule('auth/login/device/preview', '\wise\login\controller\LoginDevice@preview');
            Route::rule('auth/login/device/trust', '\wise\login\controller\LoginDevice@trust');
            Route::rule('auth/login/device/untrust', '\wise\login\controller\LoginDevice@untrust');
            Route::rule('auth/login/device/revoke', '\wise\login\controller\LoginDevice@revoke');
            Route::rule('auth/login/device/rename', '\wise\login\controller\LoginDevice@rename');

            Route::rule('auth/login/event/index', '\wise\login\controller\LoginEvent@index');
            Route::rule('auth/login/event/getList', '\wise\login\controller\LoginEvent@getList');
            Route::rule('auth/login/event/preview', '\wise\login\controller\LoginEvent@preview');
            Route::rule('auth/login/event/clearLog', '\wise\login\controller\LoginEvent@clearLog');

            Route::rule('auth/login/ip-list/index', '\wise\login\controller\LoginIpList@index');
            Route::rule('auth/login/ip-list/getList', '\wise\login\controller\LoginIpList@getList');
            Route::rule('auth/login/ip-list/add', '\wise\login\controller\LoginIpList@add');
            Route::rule('auth/login/ip-list/save', '\wise\login\controller\LoginIpList@save');
            Route::rule('auth/login/ip-list/edit', '\wise\login\controller\LoginIpList@edit');
            Route::rule('auth/login/ip-list/update', '\wise\login\controller\LoginIpList@update');
            Route::rule('auth/login/ip-list/delete', '\wise\login\controller\LoginIpList@delete');
            Route::rule('auth/login/ip-list/status', '\wise\login\controller\LoginIpList@status');
            Route::rule('auth/login/ip-list/flushCache', '\wise\login\controller\LoginIpList@flushCache');

            Route::rule('auth/login/totp/index', '\wise\login\controller\LoginTotp@index');
            Route::rule('auth/login/totp/getList', '\wise\login\controller\LoginTotp@getList');
            Route::rule('auth/login/totp/forceDisable', '\wise\login\controller\LoginTotp@forceDisable');
            Route::rule('auth/login/totp/resetSecret', '\wise\login\controller\LoginTotp@resetSecret');
            Route::rule('auth/login/totp/delete', '\wise\login\controller\LoginTotp@delete');
            Route::rule('auth/login/totp/restore', '\wise\login\controller\LoginTotp@restore');
        });
    }
}
