/**
 * auth_ip_lists.js — ESM 模块（已从 AMD 迁移）
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
                url: '/admin/auth/login/ip-list/getList',
                showColumns: true,
                pagination: true,
                dataDataField: 'data.list',
                extend: {
                    index_url: '/admin/auth/login/ip-list/index',
                    add_url: '/admin/auth/login/ip-list/add',
                    del_url: '/admin/auth/login/ip-list/delete'
                },
                toolbarBtn: ['add', 'refresh', 'export',
                    {
                        id: 'delete',
                        name: 'delete',
                        title: '批量删除',
                        icon: 'bi bi-trash',
                        disabled: true,
                        class: 'btn btn-sm btn-danger mx-1 btn-disabled',
                        click() {
                            var rows = $('#table').bootstrapTable('getSelections');
                            if (!rows || rows.length === 0) {
                                wsToast('请选择需要删除的记录', 0);
                                return;
                            }
                            wsConfirm('确定删除选中的 ' + rows.length + ' 条 IP 规则？', { title: '批量删除' }).then(function (ok) {
                                if (!ok) return;
                                var ids = rows.map(function (r) { return r.id; });
                                $.post('/admin/auth/login/ip-list/delete', {ids: ids.join(',')}, function (res) {
                                    wsToast(res.msg, res.code === OK_CODE ? 1 : 2);
                                    $('#table').bootstrapTable('refresh');
                                }, 'json');
                            });
                        }
                    },
                    {
                        id: 'flushCache',
                        name: 'flushCache',
                        title: '刷新缓存',
                        icon: 'bi bi-arrow-repeat',
                        class: 'btn btn-sm btn-info mx-1',
                        click() {
                            $.post('/admin/auth/login/ip-list/flushCache', {}, function (res) {
                                wsToast(res.msg, res.code === OK_CODE ? 1 : 2);
                            }, 'json');
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
                    field: 'cidr',
                    title: 'CIDR 网段/IP',
                    formatter: 'search',
                    align: 'left'
                }, {
                    field: 'type',
                    title: '类型',
                    formatter(value) {
                        if (value === 'blacklist') return '<span class="badge bg-danger">黑名单</span>';
                        if (value === 'whitelist') return '<span class="badge bg-success">白名单</span>';
                        return value;
                    },
                    searchList: {
                        'blacklist': '黑名单',
                        'whitelist': '白名单'
                    },
                    align: 'center',
                    width: '100'
                }, {
                    field: 'remark',
                    title: '备注',
                    formatter: 'normal',
                    align: 'left'
                }, {
                    field: 'status',
                    title: '状态',
                    formatter: 'status',
                    custom: {
                        '0': 'danger',
                        '1': 'success'
                    },
                    searchList: {
                        '0': '禁用',
                        '1': '启用'
                    },
                    align: 'center',
                    width: '80'
                }, {
                    field: 'create_time',
                    title: '创建时间',
                    formatter: 'normal',
                    align: 'left',
                    sortable: true
                }, {
                    field: 'update_time',
                    title: '更新时间',
                    formatter: 'normal',
                    align: 'left'
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
