/**
 * login_security_event.js — ESM 模块（已从 AMD 迁移）
 */
const $ = window.jQuery;
const Table = window.EnhancedTable;
const FormValidator = window.FormValidator;
/**
 * 统一 UI 门面（UIS v1.1 §4）：iframe 内取父窗口的 Wise.ui；
 * 业务侧禁止直调 layer.*（msg/alert/confirm/prompt 已由内核 toast/dialog 取代）。
 */
function wsUi() {
    let win = window;
    try {
        if (window.parent && window.parent !== window && window.parent.Wise && window.parent.Wise.ui) {
            win = window.parent;
        }
    } catch (e) { /* 跨域：用自身 */ }
    return (win.Wise && win.Wise.ui) || null;
}

/** @param {number} [icon] layer 图标约定：0 普通 / 1 成功 / 2 失败 */
function wsToast(msg, icon) {
    const ui = wsUi();
    if (!ui) return;
    ui.toast.show(msg, icon === 1 ? 'success' : (icon === 2 ? 'error' : 'info'));
}

/** @returns {Promise<boolean>} */
function wsConfirm(msg, options) {
    const ui = wsUi();
    if (!ui) return Promise.resolve(window.confirm(msg));
    return ui.dialog.confirm(msg, options || {});
}

function wsAlert(msg, options) {
    const ui = wsUi();
    if (!ui) { window.alert(msg); return; }
    ui.dialog.alert(msg, options || {});
}

/** 轻表单弹窗：唯一入口 dialog.form */
function wsForm(spec) {
    const ui = wsUi();
    if (!ui) return Promise.resolve({ success: false });
    return ui.dialog.form(spec);
}

const Controller = {
        index() {
            const table = new Table({
                idTable: 'table',
                url: '/admin/auth/login/event/getList',
                showColumns: true,
                pagination: true,
                dataDataField: 'data.list',
                extend: {
                    index_url: '/admin/auth/login/event/index',
                    preview_url: '/admin/auth/login/event/preview'
                },
                toolbarBtn: [
                    'preview', 'refresh', 'export',
                    {
                        id: 'clearLog',
                        name: 'clearLog',
                        title: '清理日志',
                        icon: 'bi bi-trash',
                        class: 'btn btn-sm btn-danger mx-1',
                        click() {
                            // 唯一入口（UIS v1.1 §4）：原「输入框 + 二次确认」两次弹层合并为一次 dialog.form
                            wsForm({
                                title: '清理历史日志',
                                size: 'sm',
                                submitText: '确认清理',
                                successMsg: '已清理',
                                action: '/admin/auth/login/event/clearLog',
                                method: 'POST',
                                html: '<div>'
                                    + '<label class="form-label" for="ws-clear-days">保留最近 N 天</label>'
                                    + '<input type="number" class="form-control" id="ws-clear-days" name="days" value="30" min="7"'
                                    + ' data-validation="required|number|min:7"'
                                    + ' data-validation-message-min="最少保留 7 天">'
                                    + '<div class="form-text">最少 7 天，默认 30 天</div>'
                                    + '<div class="form-text text-danger">清理后不可恢复</div>'
                                    + '</div>',
                                onSuccess: function () {
                                    $('#table').bootstrapTable('refresh');
                                }
                            });
                        }
                    }
                ],
                columns: [{
                    field: 'ck',
                    checkbox: true,
                    align: 'center',
                    valign: 'middle'
                }, {
                    field: 'id',
                    title: 'ID',
                    width: '60',
                    sortable: true
                }, {
                    field: 'event_type',
                    title: '事件类型',
                    formatter(value) {
                        var map = {
                            'login_failure':   '<span class="badge bg-danger">登录失败</span>',
                            'login_success':   '<span class="badge bg-success">登录成功</span>',
                            'account_locked':  '<span class="badge bg-warning text-dark">账户锁定</span>',
                            'account_unlocked':'<span class="badge bg-info">账户解锁</span>',
                            'ip_blacklisted':  '<span class="badge bg-dark">IP封禁</span>',
                            'captcha_failed':  '<span class="badge bg-secondary">验证码失败</span>',
                            'totp_verified':   '<span class="badge bg-success">TOTP验证通过</span>',
                            'totp_failed':     '<span class="badge bg-danger">TOTP验证失败</span>',
                            'device_trusted':  '<span class="badge bg-primary">设备信任</span>',
                            'device_new':      '<span class="badge bg-info">新设备</span>',
                            'device_revoked':  '<span class="badge bg-secondary">设备撤销</span>',
                            'anomaly_detected': '<span class="badge bg-warning text-dark">异常登录检测</span>',
                            'anomaly_detect_error': '<span class="badge bg-secondary">异常检测失败</span>'
                        };
                        return map[value] || value;
                    },
                    align: 'left',
                    searchList: {
                        'login_failure': '登录失败',
                        'login_success': '登录成功',
                        'account_locked': '账户锁定',
                        'account_unlocked': '账户解锁',
                        'ip_blacklisted': 'IP封禁',
                        'captcha_failed': '验证码失败',
                        'totp_verified': 'TOTP验证通过',
                        'totp_failed': 'TOTP验证失败',
                        'device_trusted': '设备信任',
                        'device_new': '新设备',
                        'device_revoked': '设备撤销',
                        'anomaly_detected': '异常登录检测',
                        'anomaly_detect_error': '异常检测失败'
                    }
                }, {
                    field: 'username',
                    title: '用户名',
                    formatter: 'normal',
                    align: 'left'
                }, {
                    field: 'ip',
                    title: 'IP地址',
                    formatter: 'search',
                    align: 'left'
                }, {
                    field: 'user_agent',
                    title: 'User-Agent',
                    formatter: 'longtext',
                    width: '200',
                    align: 'left'
                }, {
                    field: 'create_time',
                    title: '发生时间',
                    formatter: 'normal',
                    align: 'left',
                    sortable: true
                }, {
                    field: 'operate',
                    buttons: ['preview', 'del'],
                    title: '操作',
                    formatter: 'operate'
                }]
            });
        }
    };

export default Controller;
