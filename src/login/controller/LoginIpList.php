<?php
declare(strict_types=1);

namespace wise\login\controller;

use app\common\controller\traits\CrudTrait;
use think\facade\View;
use wise\login\ip\DatabaseIpListProvider;
use wise\login\model\IpList;

/**
 * 登录安全 — IP 黑白名单管理（包内后台控制器）
 *
 * 由包内 RouteRegistrar 以 `/admin/auth/login/ip-list/*` 落地，
 * 菜单见 {@see \wise\login\menu\LoginMenuProvider}。
 */
class LoginIpList extends \app\admin\controller\BaseController
{
    use CrudTrait;

    /** 视图 scope（视图驱动据此把相对模板名兜底到本包 view/ 目录） */
    protected const VIEW_SCOPE = 'wise-auth';

    protected function getModel(): \think\Model
    {
        return new IpList();
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
     * IP 黑白名单列表页
     */
    public function index()
    {
        View::assign('wsconfig', array_merge(
            (array) View::get('wsconfig'),
            ['js' => '../plugins/wise-auth/js/login_ip_list']
        ));

        return $this->fetch('admin/login_ip_list/index');
    }

    /**
     * IP 列表数据
     */
    public function getList()
    {
        $this->buildQueryParams();

        $filters = [
            'type'    => $this->request->param('type'),
            'status'  => $this->request->param('status'),
            'keyword' => $this->request->param('keyword'),
        ];

        $result = IpList::getList($this->page, $this->pagesize, $filters);

        return $this->success('success', [
            'total' => $result['total'],
            'list'  => $result['list'],
            'page'  => $this->page,
            'limit' => $this->pagesize,
        ]);
    }

    /**
     * 新增 IP 条目（GET 渲染表单）
     */
    public function add()
    {
        return $this->assign([
            'isEdit' => false,
            'row'    => null,
        ])->fetch('admin/login_ip_list/form');
    }

    /**
     * 保存新增 IP 条目（POST）
     */
    public function save()
    {
        $cidr   = trim($this->request->param('cidr', ''));
        $type   = $this->request->param('type', 'blacklist');
        $remark = trim($this->request->param('remark', ''));

        if ($cidr === '') {
            return $this->error('CIDR 网段不能为空');
        }
        if (!in_array($type, ['whitelist', 'blacklist'])) {
            return $this->error('类型必须为 whitelist 或 blacklist');
        }

        $exists = IpList::where('cidr', $cidr)->where('type', $type)->find();
        if ($exists) {
            return $this->error('该 CIDR 在同一类型下已存在');
        }

        try {
            $record = new IpList();
            $record->cidr   = $cidr;
            $record->type   = $type;
            $record->remark = mb_substr($remark, 0, 200);
            $record->status = 1;
            $record->save();

            $this->flushIpCache();
            return $this->success('添加成功');
        } catch (\Throwable $e) {
            \wise\support\context\ContextualLogger::error('[login-security] IP 条目添加失败', [
                'exception' => $e::class,
                'message'   => $e->getMessage(),
            ]);
            return $this->error('添加失败，请查看系统日志');
        }
    }

    /**
     * 编辑 IP 条目（GET 渲染表单）
     */
    public function edit()
    {
        $id  = $this->request->param('id/d', 0);
        $row = IpList::find($id);
        if (!$row) {
            return $this->error('记录不存在');
        }

        return $this->assign([
            'isEdit' => true,
            'row'    => $row,
        ])->fetch('admin/login_ip_list/form');
    }

    /**
     * 更新 IP 条目（POST）
     */
    public function update()
    {
        $id     = $this->request->param('id/d', 0);
        $remark = trim($this->request->param('remark', ''));

        $record = IpList::find($id);
        if (!$record) {
            return $this->error('记录不存在');
        }

        try {
            $record->remark = mb_substr($remark, 0, 200);
            $record->save();

            $this->flushIpCache();
            return $this->success('修改成功');
        } catch (\Throwable $e) {
            \wise\support\context\ContextualLogger::error('[login-security] IP 条目修改失败', [
                'exception' => $e::class,
                'message'   => $e->getMessage(),
            ]);
            return $this->error('修改失败，请查看系统日志');
        }
    }

    /**
     * 删除 IP 条目
     */
    public function delete()
    {
        $id = $this->request->param('id/d', 0);

        $record = IpList::find($id);
        if (!$record) {
            return $this->error('记录不存在');
        }

        try {
            $record->delete();
            $this->flushIpCache();
            return $this->success('删除成功');
        } catch (\Throwable $e) {
            \wise\support\context\ContextualLogger::error('[login-security] IP 条目删除失败', [
                'exception' => $e::class,
                'message'   => $e->getMessage(),
            ]);
            return $this->error('删除失败，请查看系统日志');
        }
    }

    /**
     * 切换启用/禁用
     */
    public function status()
    {
        $id = $this->request->param('id/d', 0);

        $record = IpList::find($id);
        if (!$record) {
            return $this->error('记录不存在');
        }

        try {
            $record->toggle();
            $this->flushIpCache();
            $msg = $record->status ? '已启用' : '已禁用';
            return $this->success($msg);
        } catch (\Throwable $e) {
            \wise\support\context\ContextualLogger::error('[login-security] IP 条目状态切换失败', [
                'exception' => $e::class,
                'message'   => $e->getMessage(),
            ]);
            return $this->error('操作失败，请查看系统日志');
        }
    }

    /**
     * 刷新 IP 列表缓存（前端按钮调用）
     */
    public function flushCache()
    {
        try {
            DatabaseIpListProvider::clearCache();
            return $this->success('IP缓存已刷新');
        } catch (\Throwable $e) {
            \wise\support\context\ContextualLogger::error('[login-security] IP 缓存刷新失败', [
                'exception' => $e::class,
                'message'   => $e->getMessage(),
            ]);
            return $this->error('缓存刷新失败，请查看系统日志');
        }
    }

    /**
     * 刷新 IP 列表缓存（内部调用）
     */
    protected function flushIpCache(): void
    {
        try {
            DatabaseIpListProvider::clearCache();
        } catch (\Throwable $e) {
        }
    }
}
