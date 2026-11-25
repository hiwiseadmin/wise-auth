/**
 * login_security_device.js — ESM 模块（已从 AMD 迁移）
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
                url: '/admin/auth/login/device/getList',
                showColumns: true,
                pagination: true,
                dataDataField: 'data.list',
                extend: {
                    index_url: '/admin/auth/login/device/index',
                    preview_url: '/admin/auth/login/device/preview',
                    del_url: '/admin/auth/login/device/revoke'
                },
                toolbarBtn: [
                    'preview', 'refresh',
                    {
                        id: 'trust',
                        name: 'trust',
                        title: '信任设备',
                        icon: 'bi bi-shield-check',
                        disabled: true,
                        class: 'btn btn-sm btn-success mx-1 btn-disabled',
                        click() {
                            var row = $('#table').bootstrapTable('getSelections');
                            if (!row || row.length === 0) {
                                wsToast('请先选择一个设备', 0);
                                return;
                            }
                            var days = parseInt(prompt('信任天数（默认30天）', '30'));
                            if (!days || days < 1) return;
                            $.post('/admin/auth/login/device/trust', {id: row[0].id, days: days}, function (res) {
                                if (res.code === OK_CODE) {
                                    wsToast('信任成功', 1);
                                    $('#table').bootstrapTable('refresh');
                                } else {
                                    wsToast(res.msg || '操作失败', 2);
                                }
                            }, 'json');
                        }
                    },
                    {
                        id: 'untrust',
                        name: 'untrust',
                        title: '取消信任',
                        icon: 'bi bi-shield-x',
                        disabled: true,
                        class: 'btn btn-sm btn-warning mx-1 btn-disabled',
                        click() {
                            var row = $('#table').bootstrapTable('getSelections');
                            if (!row || row.length === 0) {
                                wsToast('请先选择一个设备', 0);
                                return;
                            }
                            wsConfirm('确定取消信任该设备？', { title: '取消信任' }).then(function (ok) {
                                if (!ok) return;
                                $.post('/admin/auth/login/device/untrust', {id: row[0].id}, function (res) {
                                    if (res.code === OK_CODE) {
                                        wsToast('已取消信任', 1);
                                        $('#table').bootstrapTable('refresh');
                                    } else {
                                        wsToast(res.msg || '操作失败', 2);
                                    }
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
                    field: 'user_id',
                    title: '用户ID',
                    formatter: 'normal',
                    align: 'left',
                    width: '80'
                }, {
                    field: 'device_name',
                    title: '设备名称',
                    formatter: 'normal',
                    align: 'left'
                }, {
                    field: 'ip',
                    title: '最近IP',
                    formatter: 'search',
                    align: 'left'
                }, {
                    field: 'is_trusted',
                    title: '信任状态',
                    formatter: 'status',
                    custom: {
                        '0': 'danger',
                        '1': 'success'
                    },
                    searchList: {
                        '0': '未信任',
                        '1': '已信任'
                    }
                }, {
                    field: 'last_used_at',
                    title: '最后使用',
                    formatter(value) {
                        return value > 0 ? new Date(value * 1000).toLocaleString() : '-';
                    },
                    align: 'left'
                }, {
                    field: 'create_time',
                    title: '首次记录',
                    formatter: 'normal',
                    align: 'left'
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
