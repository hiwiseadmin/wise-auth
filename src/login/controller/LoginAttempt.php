<?php
declare(strict_types=1);

namespace wise\login\controller;

use app\common\controller\traits\CrudTrait;
use think\facade\View;
use wise\login\event\EventLogger;
use wise\login\model\FailedAttempt;

/**
 * 登录安全 — 失败尝试管理（包内后台控制器）
 *
 * 由包内 RouteRegistrar 以 `/admin/login_attempt/*` 落地，
 * 菜单见 {@see \wise\login\menu\LoginMenuProvider}。
 *
 * 视图归属：控制器继承宿主 app\admin\controller\BaseController，
 * initialize() 中 ViewScope::activate('wise-auth.login')，使显式模板名
 * `admin/login_attempt/index` 兜底到本包 view/ 目录；
 * 宿主 app/admin/view/** 放同名文件仍可覆盖（L1 优先）。
 *
 * 前端 ESM 模块随包发布：`../plugins/wise-auth/js/login_attempt`
 * （源文件为本包 `public/js/login_attempt.js`，由 `wise:vendor:publish`
 * 复制到应用的 `public/statics/plugins/wise-login-security/`）。
 */
class LoginAttempt extends \app\admin\controller\BaseController
{
    use CrudTrait;

    /** 视图 scope（视图驱动据此把相对模板名兜底到本包 view/ 目录） */
    protected const VIEW_SCOPE = 'wise-auth';

    protected function getModel(): \think\Model
    {
        return new FailedAttempt();
    }

    protected function initialize()
    {
        parent::initialize();

        try {
            if (class_exists(\app\common\view\ViewScope::class)) {
                \app\common\view\ViewScope::activate(self::VIEW_SCOPE);
            } else {
                $this->request->view_scope = self::VIEW_SCOPE;
            }
        } catch (\Throwable $e) {
        }
    }

    /**
     * 失败尝试列表页
     */
    public function index()
    {
        View::assign('wsconfig', array_merge(
            (array) View::get('wsconfig'),
            ['js' => '../plugins/wise-auth/js/login_attempt']
        ));

        return $this->fetch('admin/login_attempt/index');
    }

    /**
     * 失败尝试列表数据
     */
    public function getList()
    {
        $this->buildQueryParams();

        $filters = [
            'keyword'      => $this->request->param('keyword'),
            'show_expired' => $this->request->param('show_expired', false),
        ];

        $result = FailedAttempt::getList($this->page, $this->pagesize, $filters);

        return $this->success('success', [
            'total' => $result['total'],
            'list'  => $result['list'],
            'page'  => $this->page,
            'limit' => $this->pagesize,
        ]);
    }

    /**
     * 手动解锁（按记录 ID 删除失败记录）
     *
     * 安全说明：
     *  - 操作写入安全事件审计日志（含被解锁用户名和操作人）
     */
    public function unlock()
    {
        $id  = $this->request->param('id/d', 0);
        $ids = $this->request->param('ids/a', []);

        if (empty($id) && empty($ids)) {
            return $this->error('参数错误：未提供记录 ID');
        }

        $idList = !empty($ids) ? array_filter(array_map('intval', $ids), function ($v) {
            return $v > 0;
        }) : [$id];

        if (empty($idList)) {
            return $this->error('参数错误：ID 无效');
        }

        $records = FailedAttempt::whereIn('id', $idList)->select();
        if ($records->isEmpty()) {
            return $this->error('记录不存在或已过期');
        }

        $count = 0;
        try {
            $lockManager = app(\wise\login\lock\LoginLockManager::class);

            foreach ($records as $record) {
                $cacheKey = (string) ($record->cache_key ?? '');
                $segments = explode('|', $cacheKey);
                $username = str_contains($cacheKey, 'user|') ? (string) end($segments) : '';

                $record->delete();

                if ($username !== '') {
                    $lockManager->unlockByUsername($username);
                }

                $this->logSecurityEvent('account_unlocked', [
                    'target_username' => $username,
                    'cache_key'       => $cacheKey,
                    'operator_id'     => auth_id('admin'),
                ], $username);

                $count++;
            }

            return $this->success('已解锁 ' . $count . ' 条失败记录');
        } catch (\Throwable $e) {
            \wise\support\context\ContextualLogger::error('[login-security] 手动解锁失败', [
                'exception' => $e::class,
                'message'   => $e->getMessage(),
            ]);
            return $this->error('解锁失败，请查看系统日志');
        }
    }

    /**
     * 清理已过期的失败记录
     */
    public function clearExpired()
    {
        try {
            $deleted = FailedAttempt::clearExpired();

            $this->logSecurityEvent('failed_attempts_cleared', [
                'deleted_count' => $deleted,
                'operator_id'   => auth_id('admin'),
            ]);

            return $this->success("已清理过期记录，共 {$deleted} 条");
        } catch (\Throwable $e) {
            \wise\support\context\ContextualLogger::error('[login-security] 清理过期失败记录失败', [
                'exception' => $e::class,
                'message'   => $e->getMessage(),
            ]);
            return $this->error('清理失败，请查看系统日志');
        }
    }

    /**
     * 记录安全审计日志
     */
    protected function logSecurityEvent(string $type, array $data, ?string $username = null): void
    {
        try {
            $logger = app(EventLogger::class);
            $logger->log($type, $data, $this->request, $username);
        } catch (\Throwable $e) {
        }
    }
}
