<?php
declare(strict_types=1);

namespace wise\login\controller;

use app\common\controller\traits\CrudTrait;
use think\facade\View;
use wise\login\device\DeviceManager;
use wise\login\event\EventLogger;
use wise\login\model\UserDevice;

/**
 * 登录安全 — 设备管理（包内后台控制器）
 *
 * 由包内 RouteRegistrar 以 `/admin/login_device/*` 落地，
 * 菜单见 {@see \wise\login\menu\LoginMenuProvider}。
 */
class LoginDevice extends \app\admin\controller\BaseController
{
    use CrudTrait;

    /** 视图 scope（视图驱动据此把相对模板名兜底到本包 view/ 目录） */
    protected const VIEW_SCOPE = 'wise-auth';

    protected function getModel(): \think\Model
    {
        return new UserDevice();
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
     * 设备列表页
     */
    public function index()
    {
        View::assign('wsconfig', array_merge(
            (array) View::get('wsconfig'),
            ['js' => '../plugins/wise-auth/js/login_device']
        ));

        return $this->fetch('admin/login_device/index');
    }

    /**
     * 设备列表数据
     */
    public function getList()
    {
        $this->buildQueryParams();

        $filters = [
            'keyword'    => $this->request->param('keyword'),
            'is_trusted' => $this->request->param('is_trusted'),
            'date_start' => $this->request->param('date_start'),
            'date_end'   => $this->request->param('date_end'),
        ];

        $result = UserDevice::getList($this->page, $this->pagesize, $filters);

        return $this->success('success', [
            'total' => $result['total'],
            'list'  => $result['list'],
            'page'  => $this->page,
            'limit' => $this->pagesize,
        ]);
    }

    /**
     * 设备详情
     */
    public function preview()
    {
        $id = $this->request->param('id/d', 0);
        $device = UserDevice::find($id);

        if (!$device) {
            return $this->error('设备不存在');
        }

        return $this->assign(['device' => $device])->fetch('admin/login_device/preview');
    }

    /**
     * 信任设备
     *
     * 安全说明：操作写入审计日志
     */
    public function trust()
    {
        $id   = $this->request->param('id/d', 0);
        $days = $this->request->param('days/d', 30);

        $device = UserDevice::find($id);
        if (!$device) {
            return $this->error('设备不存在');
        }

        try {
            $device->trust($days);

            $this->logSecurityEvent('device_trusted', [
                'device_id'    => $id,
                'device_ua'    => mb_substr($device->user_agent ?? '', 0, 200),
                'target_user'  => $device->user_id,
                'trust_days'   => $days,
                'operator_id'  => auth_id('admin'),
            ], $device->user_id > 0 ? (string) $device->user_id : null);

            return $this->success('设备已信任');
        } catch (\Throwable $e) {
            \wise\support\context\ContextualLogger::error('[login-security] 设备信任失败', [
                'exception' => $e::class,
                'message'   => $e->getMessage(),
            ]);
            return $this->error('信任失败，请查看系统日志');
        }
    }

    /**
     * 取消信任
     *
     * 安全说明：操作写入审计日志
     */
    public function untrust()
    {
        $id = $this->request->param('id/d', 0);

        $device = UserDevice::find($id);
        if (!$device) {
            return $this->error('设备不存在');
        }

        try {
            $device->untrust();

            $this->logSecurityEvent('device_untrusted', [
                'device_id'    => $id,
                'device_ua'    => mb_substr($device->user_agent ?? '', 0, 200),
                'target_user'  => $device->user_id,
                'operator_id'  => auth_id('admin'),
            ], $device->user_id > 0 ? (string) $device->user_id : null);

            return $this->success('已取消信任');
        } catch (\Throwable $e) {
            \wise\support\context\ContextualLogger::error('[login-security] 设备取消信任失败', [
                'exception' => $e::class,
                'message'   => $e->getMessage(),
            ]);
            return $this->error('操作失败，请查看系统日志');
        }
    }

    /**
     * 撤销设备（调用 DeviceManager::revoke 删除记录 + 记录事件）
     *
     * 安全说明：操作写入审计日志（DeviceManager::revoke 也会记录）
     */
    public function revoke()
    {
        $id = $this->request->param('id/d', 0);

        $device = UserDevice::find($id);
        if (!$device) {
            return $this->error('设备不存在');
        }

        try {
            $targetUserId = (int) $device->user_id;

            $deviceManager = app(DeviceManager::class);
            $deviceManager->revoke($targetUserId, $id);

            $this->logSecurityEvent('device_revoked', [
                'device_id'    => $id,
                'device_ua'    => mb_substr($device->user_agent ?? '', 0, 200),
                'target_user'  => $targetUserId,
                'operator_id'  => auth_id('admin'),
            ], $targetUserId > 0 ? (string) $targetUserId : null);

            return $this->success('设备已撤销');
        } catch (\Throwable $e) {
            \wise\support\context\ContextualLogger::error('[login-security] 设备撤销失败', [
                'exception' => $e::class,
                'message'   => $e->getMessage(),
            ]);
            return $this->error('撤销失败，请查看系统日志');
        }
    }

    /**
     * 重命名设备
     *
     * 安全说明：操作写入审计日志
     */
    public function rename()
    {
        $id   = $this->request->param('id/d', 0);
        $name = $this->request->param('name', '');

        if (mb_strlen($name) < 1 || mb_strlen($name) > 50) {
            return $this->error('设备名称长度需在 1-50 字符之间');
        }

        $device = UserDevice::find($id);
        if (!$device) {
            return $this->error('设备不存在');
        }

        $oldName = $device->device_name ?? '';

        try {
            $deviceManager = app(DeviceManager::class);
            $deviceManager->rename((int) $device->user_id, $id, $name);

            $this->logSecurityEvent('device_renamed', [
                'device_id'    => $id,
                'old_name'     => $oldName,
                'new_name'     => $name,
                'target_user'  => $device->user_id,
                'operator_id'  => auth_id('admin'),
            ], $device->user_id > 0 ? (string) $device->user_id : null);

            return $this->success('重命名成功');
        } catch (\Throwable $e) {
            \wise\support\context\ContextualLogger::error('[login-security] 设备重命名失败', [
                'exception' => $e::class,
                'message'   => $e->getMessage(),
            ]);
            return $this->error('重命名失败，请查看系统日志');
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
