<?php
declare(strict_types=1);

namespace wise\login\controller;

use app\common\controller\traits\CrudTrait;
use think\facade\View;
use wise\login\model\SecurityEvent;

/**
 * 登录安全 — 安全事件日志（包内后台控制器）
 *
 * 由包内 RouteRegistrar 以 `/admin/login_event/*` 落地，
 * 菜单见 {@see \wise\login\menu\LoginMenuProvider}。
 */
class LoginEvent extends \app\admin\controller\BaseController
{
    use CrudTrait;

    /** 视图 scope（视图驱动据此把相对模板名兜底到本包 view/ 目录） */
    protected const VIEW_SCOPE = 'wise-auth';

    protected function getModel(): \think\Model
    {
        return new SecurityEvent();
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
     * 事件日志列表页
     */
    public function index()
    {
        View::assign('wsconfig', array_merge(
            (array) View::get('wsconfig'),
            ['js' => '../plugins/wise-auth/js/login_event']
        ));

        return $this->fetch('admin/login_event/index');
    }

    /**
     * 事件列表数据
     */
    public function getList()
    {
        $this->buildQueryParams();

        $filters = [
            'event_type' => $this->request->param('event_type'),
            'username'   => $this->request->param('username'),
            'ip'         => $this->request->param('ip'),
            'date_start' => $this->request->param('date_start'),
            'date_end'   => $this->request->param('date_end'),
        ];

        $result = SecurityEvent::getList($this->page, $this->pagesize, $filters);

        return $this->success('success', [
            'total' => $result['total'],
            'list'  => $result['list'],
            'page'  => $this->page,
            'limit' => $this->pagesize,
        ]);
    }

    /**
     * 事件详情预览
     */
    public function preview()
    {
        $id    = $this->request->param('id/d', 0);
        $event = SecurityEvent::find($id);

        if (!$event) {
            return $this->error('事件不存在');
        }

        $details = $event->details ? json_decode($event->details, true) : [];

        return $this->assign([
            'event'   => $event,
            'details' => $details,
        ])->fetch('admin/login_event/preview');
    }

    /**
     * 清理 N 天前的事件
     */
    public function clearLog()
    {
        $days = $this->request->param('days/d', 30);
        if ($days < 7) {
            return $this->error('最少保留 7 天');
        }

        try {
            $deleted = SecurityEvent::clearOlderThan($days);
            return $this->success("已清理 {$days} 天前的安全事件，共 {$deleted} 条");
        } catch (\Throwable $e) {
            \wise\support\context\ContextualLogger::error('[login-security] 清理安全事件失败', [
                'exception' => $e::class,
                'message'   => $e->getMessage(),
            ]);
            return $this->error('清理失败，请查看系统日志');
        }
    }
}
