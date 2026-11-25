/**
 * login_security_totp.js — ESM 模块（已从 AMD 迁移）
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
                url: '/admin/auth/login/totp/getList',
                showColumns: true,
                pagination: true,
                dataDataField: 'data.list',
                extend: {
                    index_url: '/admin/auth/login/totp/index',
                    del_url: '/admin/auth/login/totp/delete'
                },
                toolbarBtn: ['refresh', 'export',
                    {
                        id: 'delete',
                        name: 'delete',
                        title: '批量删除',
                        icon: 'bi bi-trash',
                        class: 'btn btn-sm btn-danger mx-1',
                        click() {
                            var rows = $('#table').bootstrapTable('getSelections');
                            if (!rows || rows.length === 0) {
                                wsToast('请选择需要删除的记录', 0);
                                return;
                            }
                            wsConfirm('确定删除选中的 ' + rows.length + ' 条 TOTP 配置？此操作会使对应用户无法完成 2FA 登录。', { title: '批量删除' }).then(function (ok) {
                                if (!ok) return;
                                var ids = rows.map(function (r) { return r.id; });
                                $.post('/admin/auth/login/totp/delete', { ids: ids.join(',') }, function (res) {
                                    wsToast(res.msg, res.code === OK_CODE ? 1 : 2);
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
                    field: 'user_type',
                    title: '用户类型',
                    formatter: 'search',
                    searchList: {
                        'admin': '管理员',
                        'member': '会员'
                    },
                    align: 'center',
                    width: '90'
                }, {
                    field: 'user_id',
                    title: '用户ID',
                    formatter: 'normal',
                    align: 'center',
                    width: '80'
                }, {
                    field: 'totp_enabled',
                    title: 'TOTP 状态',
                    formatter: 'status',
                    custom: {
                        '0': 'danger',
                        '1': 'success'
                    },
                    searchList: {
                        '0': '未启用',
                        '1': '已启用'
                    },
                    align: 'center',
                    width: '100'
                }, {
                    field: 'secret_masked',
                    title: 'TOTP 密钥',
                    formatter(value) {
                        if (!value) return '<span class="text-muted">—</span>';
                        // 服务端只返回掩码值（前 8 位 + ••••），明文密钥不出接口
                        return '<code>' + value + '</code>';
                    },
                    align: 'left'
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
