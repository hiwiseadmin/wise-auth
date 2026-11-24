<?php
declare(strict_types=1);

namespace wise\login\controller;

use app\common\controller\traits\CrudTrait;
use think\facade\View;
use wise\login\event\EventLogger;
use wise\login\model\TotpConfig;

/**
 * 登录安全 — TOTP 双因素认证管理（包内后台控制器）
 *
 * 由包内 RouteRegistrar 以 `/admin/login_totp/*` 落地，
 * 菜单见 {@see \wise\login\menu\LoginMenuProvider}。
 */
class LoginTotp extends \app\admin\controller\BaseController
{
    use CrudTrait;

    /** 视图 scope（视图驱动据此把相对模板名兜底到本包 view/ 目录） */
    protected const VIEW_SCOPE = 'wise-auth';

    protected function getModel(): \think\Model
    {
        return new TotpConfig();
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
     * TOTP 管理列表页
     */
    public function index()
    {
        View::assign('wsconfig', array_merge(
            (array) View::get('wsconfig'),
            ['js' => '../plugins/wise-auth/js/login_totp']
        ));

        return $this->fetch('admin/login_totp/index');
    }

    /**
     * TOTP 配置列表数据
     */
    public function getList()
    {
        $this->buildQueryParams();

        $filters = [
            'user_type' => $this->request->param('user_type'),
            'enabled'   => $this->request->param('enabled'),
            'keyword'   => $this->request->param('keyword'),
        ];

        $result = TotpConfig::getList($this->page, $this->pagesize, $filters);

        return $this->success('success', [
            'total' => $result['total'],
            'list'  => $result['list'],
            'page'  => $this->page,
            'limit' => $this->pagesize,
        ]);
    }

    /**
     * 强制关闭指定用户的 TOTP
     *
     * 安全说明：
     *  - 仅超级管理员可执行此操作
     *  - 操作写入安全事件审计日志
     */
    public function forceDisable()
    {
        $id = $this->request->param('id/d', 0);

        $config = TotpConfig::find($id);
        if (!$config) {
            return $this->error('TOTP 配置不存在');
        }

        try {
            $config->forceDisable();

            $this->logSecurityEvent('totp_force_disable', [
                'target_user_id'   => $config->user_id,
                'target_user_type' => $config->user_type,
                'operator_id'      => auth_id('admin'),
            ], $config->user_id > 0 ? (string) $config->user_id : null);

            return $this->success('已强制关闭 TOTP');
        } catch (\Throwable $e) {
            \wise\support\context\ContextualLogger::error('[login-security] TOTP 配置操作失败', [
                'exception' => $e::class,
                'message'   => $e->getMessage(),
            ]);
            return $this->error('操作失败，请查看系统日志');
        }
    }

    /**
     * 重置用户密钥（用户下次登录需重新绑定 TOTP）
     *
     * 安全说明：
     *  - 仅超级管理员可执行此操作
     *  - 操作写入安全事件审计日志
     */
    public function resetSecret()
    {
        $id = $this->request->param('id/d', 0);

        $config = TotpConfig::find($id);
        if (!$config) {
            return $this->error('TOTP 配置不存在');
        }

        try {
            $config->resetSecret();

            $this->logSecurityEvent('totp_secret_reset', [
                'target_user_id'   => $config->user_id,
                'target_user_type' => $config->user_type,
                'operator_id'      => auth_id('admin'),
            ], $config->user_id > 0 ? (string) $config->user_id : null);

            return $this->success('密钥已重置，用户下次登录需重新绑定');
        } catch (\Throwable $e) {
            \wise\support\context\ContextualLogger::error('[login-security] TOTP 配置操作失败', [
                'exception' => $e::class,
                'message'   => $e->getMessage(),
            ]);
            return $this->error('操作失败，请查看系统日志');
        }
    }

    /**
     * 删除 TOTP 配置（支持批量）
     *
     * 前端 EnhancedTable 删除链路会以下列任一形式传参：
     *   - 批量：ids = [1,2,3]（数组）或 "1,2,3"（逗号串）
     *   - 单行：id = 1
     *
     * 删除为**软删除**（记录保留，可由 restore() 撤销）；
     * 删除后该用户将无法完成 2FA 登录，属高危操作，逐条写入安全事件审计日志。
     */
    public function delete()
    {
        $ids = $this->request->param('ids', []);
        $id  = $this->request->param('id/d', 0);

        if (is_string($ids) && $ids !== '') {
            $ids = explode(',', $ids);
        }

        $idList = is_array($ids) ? array_map('intval', $ids) : [];
        if ($id > 0) {
            $idList[] = $id;
        }

        $idList = array_values(array_unique(array_filter($idList, static function ($v) {
            return $v > 0;
        })));

        if (empty($idList)) {
            return $this->error('参数错误：未提供记录 ID');
        }

        $records = TotpConfig::whereIn('id', $idList)->select();
        if ($records->isEmpty()) {
            return $this->error('配置不存在或已删除');
        }

        try {
            $count = 0;
            foreach ($records as $record) {
                $targetUserId   = (int) $record->user_id;
                $targetUserType = (string) $record->user_type;

                $record->delete();

                $this->logSecurityEvent('totp_config_deleted', [
                    'target_user_id'   => $targetUserId,
                    'target_user_type' => $targetUserType,
                    'operator_id'      => auth_id('admin'),
                ], $targetUserId > 0 ? (string) $targetUserId : null);

                $count++;
            }

            return $this->success("已删除 {$count} 条 TOTP 配置");
        } catch (\Throwable $e) {
            \wise\support\context\ContextualLogger::error('[login-security] TOTP 配置删除失败', [
                'exception' => $e::class,
                'message'   => $e->getMessage(),
            ]);
            return $this->error('删除失败，请查看系统日志');
        }
    }

    /**
     * 恢复已删除的 TOTP 配置（支持批量）
     *
     * 与 delete() 互逆：清除 delete_time 使记录重新生效（含密钥 / 备份码 / 恢复码），
     * 前端删除 Toast 的「撤销」按钮即调用本动作。
     *
     * 传参形式与 delete() 一致：ids = [..] / "1,2,3" 或单行 id。
     *
     * 安全说明：恢复后该用户的 2FA 配置重新生效，逐条写入安全事件审计日志。
     */
    public function restore()
    {
        $ids = $this->request->param('ids', []);
        $id  = $this->request->param('id/d', 0);

        if (is_string($ids) && $ids !== '') {
            $ids = explode(',', $ids);
        }

        $idList = is_array($ids) ? array_map('intval', $ids) : [];
        if ($id > 0) {
            $idList[] = $id;
        }

        $idList = array_values(array_unique(array_filter($idList, static function ($v) {
            return $v > 0;
        })));

        if (empty($idList)) {
            return $this->error('参数错误：未提供记录 ID');
        }

        $records = TotpConfig::onlyTrashed()->whereIn('id', $idList)->select();
        if ($records->isEmpty()) {
            return $this->error('记录不存在或未被删除');
        }

        try {
            $count = 0;
            foreach ($records as $record) {
                $targetUserId   = (int) $record->user_id;
                $targetUserType = (string) $record->user_type;

                $record->restore();

                $this->logSecurityEvent('totp_config_restored', [
                    'target_user_id'   => $targetUserId,
                    'target_user_type' => $targetUserType,
                    'operator_id'      => auth_id('admin'),
                ], $targetUserId > 0 ? (string) $targetUserId : null);

                $count++;
            }

            return $this->success("已恢复 {$count} 条 TOTP 配置");
        } catch (\Throwable $e) {
            \wise\support\context\ContextualLogger::error('[login-security] TOTP 配置恢复失败', [
                'exception' => $e::class,
                'message'   => $e->getMessage(),
            ]);
            return $this->error('恢复失败，请查看系统日志');
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
