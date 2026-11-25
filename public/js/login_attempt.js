/**
 * login_security_attempt.js — ESM 模块（已从 AMD 迁移）
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

const OK_CODE = 0;

const Controller = {
        index() {
            const table = new Table({
                idTable: 'table',
                url: '/admin/auth/login/attempt/getList',
                showColumns: true,
                pagination: true,
                dataDataField: 'data.list',
                extend: {
                    index_url: '/admin/auth/login/attempt/index',
                    del_url: '/admin/auth/login/attempt/unlock'
                },
                toolbarBtn: ['refresh', 'export',
                    {
                        id: 'delete',
                        name: 'delete',
                        title: '批量删除',
                        icon: 'bi bi-trash',
                        disabled: true,
                        class: 'btn btn-sm btn-danger btn-disabled mx-1',
                        click() {
                            var rows = $('#table').bootstrapTable('getSelections');
                            if (!rows || rows.length === 0) {
                                wsAlert('请选择需要删除的记录', { title: '提示' });
                                return;
                            }
                            wsConfirm('确定删除选中的 ' + rows.length + ' 条失败记录？', { title: '批量删除' }).then(function (ok) {
                                if (!ok) return;
                                var ids = rows.map(function (r) { return r.id; });
                                $.post('/admin/auth/login/attempt/unlock', {ids: ids}, function (res) {
                                    wsAlert(res.msg, { title: res.code === OK_CODE ? '操作成功' : '操作失败' });
                                    $('#table').bootstrapTable('refresh');
                                }, 'json');
                            });
                        }
                    },
                    {
                        id: 'clearExpired',
                        name: 'clearExpired',
                        title: '清理过期',
                        icon: 'bi bi-eraser',
                        class: 'btn btn-sm btn-warning mx-1',
                        click() {
                            wsConfirm('确定清理所有已过期的失败记录？', { title: '清理过期' }).then(function (ok) {
                                if (!ok) return;
                                $.post('/admin/auth/login/attempt/clearExpired', {}, function (res) {
                                    wsAlert(res.msg, { title: res.code === OK_CODE ? '操作成功' : '操作失败' });
                                    $('#table').bootstrapTable('refresh');
                                }, 'json');
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
                    field: 'cache_key',
                    title: '缓存键',
                    formatter: 'search',
                    align: 'left'
                }, {
                    field: 'attempts',
                    title: '失败次数',
                    formatter: 'status',
                    custom: {
                        '1': 'warning',
                        '2': 'warning',
                        '3': 'warning',
                        '4': 'warning',
                        '5': 'danger'
                    },
                    searchList: {
                        '1': '1 次',
                        '2': '2 次',
                        '3': '3 次',
                        '4': '4 次',
                        '5': '≥5 次'
                    },
                    sortable: true,
                    align: 'center',
                    width: '100'
                }, {
                    field: 'expire_at',
                    title: '锁定到期',
                    formatter(value) {
                        if (!value || value <= 0) return '<span class="badge bg-danger">永久</span>';
                        var now = Math.floor(Date.now() / 1000);
                        if (value <= now) return '<span class="badge bg-secondary">已过期</span>';
                        var remaining = Math.ceil((value - now) / 60);
                        return '<span class="badge bg-danger">' + remaining + ' 分钟后</span>';
                    },
                    sortable: true,
                    align: 'left'
                }, {
                    field: 'create_time',
                    title: '首次失败',
                    formatter: 'normal',
                    align: 'left',
                    sortable: true
                }, {
                    field: 'update_time',
                    title: '最近失败',
                    formatter: 'normal',
                    align: 'left',
                    sortable: true
                }, {
                    field: 'operate',
                    buttons: ['del'],
                    title: '操作',
                    formatter: 'operate'
                }]
            });
        }
    };

export default Controller;
