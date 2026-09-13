macro_rules! format {
    ($language:expr, $english:literal, $chinese:literal $(, $($arguments:tt)*)?) => {
        match $language {
            crate::Language::English => std::format!($english $(, $($arguments)*)?),
            crate::Language::Chinese => std::format!($chinese $(, $($arguments)*)?),
        }
    };
}
pub(crate) use format;

/// Display language belongs to this TUI session, never to domain data.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Language {
    #[default]
    English,
    Chinese,
}

impl Language {
    pub(crate) fn reason(self, reason: &'static str) -> &'static str {
        match reason {
            "select_current_proposal" => {
                self.text("Select a current proposal first", "请先选择当前提议")
            }
            "proposal_detail_required" => self.text(
                "Open the exact proposal detail before acting",
                "请先打开提议的精确详情",
            ),
            "atomic_plain_acceptance_unavailable" => self.text(
                "The current daemon review does not permit direct acceptance",
                "当前服务端复核不允许直接接受",
            ),
            "atomic_merge_and_accept_unavailable" => self.text(
                "The current daemon review does not permit merging",
                "当前服务端复核不允许合并",
            ),
            "atomic_edit_and_accept_unavailable" => self.text(
                "This proposal does not support the existing edit-and-accept operation",
                "此提议不支持现有的编辑并接受操作",
            ),
            "support_replacement_unavailable" => self.text(
                "No editable replacement was supplied for this support state",
                "当前支持状态未提供可编辑的替换内容",
            ),
            "support_deprecate_unavailable" => self.text(
                "Deprecation is not available for this support state",
                "当前支持状态不可弃用",
            ),
            "configuration_requires_file_read" => self.text(
                "Read the configuration document before editing",
                "编辑前请先读取配置文档",
            ),
            "proposal_document_too_large" => self.text(
                "The proposal exceeds the bounded editor limit",
                "提议超过编辑器的有界大小限制",
            ),
            "proposal_action_unavailable" => self.text(
                "The existing proposal conditions do not permit this operation",
                "现有提议条件不允许此操作",
            ),
            _ => self.label(reason),
        }
    }

    /// Only call for application-owned labels, never user content or rendered text.
    pub(crate) fn label(self, english: &'static str) -> &'static str {
        if self == Self::English {
            return english;
        }
        match english {
            "Diagnostics" => "诊断",
            "History" => "历史",
            "Technical" => "技术",
            "proposal" => "提议",
            "support/revalidation" => "支持／重新验证",
            "negative review" => "负面复核",
            "segmentation correction" => "分段修正",
            "recovery correction" => "恢复修正",
            "work assignment" => "工作分配",
            "competing resolution" => "竞争解决",
            "attempt resume" => "尝试恢复",
            "lane lifecycle" => "通道生命周期",
            "capture integrity" => "采集完整性",
            "worktree lineage" => "工作树沿革",
            "review hold" => "等待复核",
            "repository lineage" => "仓库沿革",
            "work execution" => "工作记录",
            "semantic asset" => "语义资料",
            "procedure" => "可复用步骤",
            "experiment/artifact" => "实验／产物",
            "recovery evidence" => "恢复证据",
            "evidence/provenance" => "证据／来源",
            "runtime status" => "运行状态",
            "derived projection" => "派生索引",
            "session import" => "会话导入",
            "semantic derivation" => "语义派生",
            "Observed message; acceptance or task intent not established" => {
                "观测到的消息；尚不能证明接受或任务意图"
            }
            "protected presentation unavailable" => "受保护内容不可显示",
            "edit-and-accept: unavailable" => "编辑并接受：不可用",
            "Unknown coverage blocks automatic acceptance, not manual review." => {
                "未知覆盖会阻止自动接受；人工复核仍可进行。"
            }
            "re-authorize forgotten object: available" => "重新授权已遗忘对象：可用",
            "R re-authorize forgotten object" => "R 重新授权已遗忘对象",
            "[/] choose; c stages selected winner; Enter confirms; Esc cancels" => {
                "[/] 选择；c 准备选中胜出项；Enter 确认；Esc 取消"
            }
            "Shared source/Evidence is retained by default; this is not source erasure." => {
                "默认保留共享来源／证据；此操作不擦除来源。"
            }
            "F stages human-only Forget; Enter confirms once; Esc cancels" => {
                "F 准备人工遗忘；Enter 确认一次；Esc 取消"
            }
            "Shared Evidence/CAS is retained; this is not source erasure." => {
                "保留共享证据／CAS；此操作不擦除来源。"
            }
            "P opens stable-ID re-entry; strict source erasure is unavailable; Esc cancels" => {
                "P 打开重新输入稳定 ID；严格来源擦除不可用；Esc 取消"
            }
            "Native history cleanup: unavailable now" => "宿主原生历史清理：当前不可用",
            "Product purge does not run this." => "产品清除不会执行此操作。",
            "External reader exclusion is unverified." => "外部读取者是否已排除尚未验证。",
            "Prune: not started/confirmed" => "版本清理：未开始／未确认",
            "D disable; E verify and enable; R rescan (exact selected context)" => {
                "D 停用；E 验证并启用；R 重新扫描（绑定精确选择）"
            }
            "Presence is not routing, adoption, or automatic Procedure coverage." => {
                "存在资料不代表已路由、采用或自动覆盖可复用步骤。"
            }
            "Provider NotChecked does not mean healthy; this view never calls the model." => {
                "模型 NotChecked 表示未检查，不等于健康；本页不会调用模型。"
            }
            "Capture / storage / model diagnostics" => "采集／存储／模型诊断",
            "No confirmed published path" => "没有已确认的发布路径",
            "No other competing candidate" => "没有其他竞争候选",
            "open detail" => "查看详情",
            "type (current page)" => "类型（当前页）",
            "scope (current page)" => "范围（当前页）",
            "state (current page)" => "状态（当前页）",
            "content" => "内容",
            "technical fields" => "技术字段",
            "sources" => "来源",
            "open task result" => "查看任务结果",
            "open sources / dependencies" => "查看来源／依赖",
            "revision history" => "修订历史",
            "select / unselect for export" => "加入／移出导出选择",
            "accept proposal" => "接受提议",
            "merge and accept" => "合并并接受",
            "defer proposal" => "延后提议",
            "reject proposal" => "拒绝提议",
            "edit and accept" => "编辑并接受",
            "submit replacement" => "提交替换提议",
            "submit deprecation" => "提交弃用提议",
            "resolve as ineffective" => "标记为无效",
            "dismiss attribution" => "驳回归因",
            "confirm harm" => "确认有害",
            "request revision" => "请求修订",
            "forget object (preview)" => "遗忘对象（预览）",
            "purge repository (preview)" => "清除仓库（预览）",
            "mark new attempt" => "标记新尝试",
            "choose competing attempt" => "选择竞争尝试",
            "previous competing candidate" => "上个竞争候选",
            "next competing candidate" => "下个竞争候选",
            "recover patch" => "恢复补丁",
            "recover files" => "恢复文件",
            "recover index" => "恢复索引",
            "recover mixed" => "混合恢复",
            "first result on this page" => "本页第一个结果",
            "second result on this page" => "本页第二个结果",
            "third result on this page" => "本页第三个结果",
            "overview" => "概览",
            "jobs" => "任务",
            "capture and diagnostics" => "采集与诊断",
            "configuration" => "配置",
            "maintenance" => "维护",
            "edit configuration" => "编辑配置",
            "submit backup job" => "提交备份任务",
            "submit backup verification" => "提交备份验证",
            "submit orphan gc" => "提交孤立文件回收",
            "export selected objects" => "导出选中对象",
            "restore (offline instructions)" => "恢复（离线说明）",
            "enable repository" => "启用仓库",
            "disable repository" => "停用仓库",
            "rescan repository" => "重新扫描仓库",
            "filter / find loaded content" => "筛选／查找已加载内容",
            "clear filter / find" => "清除筛选／查找",
            "previous match" => "上个匹配",
            "next match" => "下个匹配",
            "zoom / restore current area" => "展开／还原当前区域",
            "first page" => "首页",
            "refresh" => "刷新",
            "back" => "返回",
            "inbox" => "待处理",
            "explorer" => "浏览",
            "system" => "系统",
            "commands" => "命令",
            "help" => "帮助",
            "quit" => "退出",
            "next page" => "下一页",
            "select a matching item" => "请先选择匹配项",
            "no supported source relation" => "此类型未提供可读取的来源关系",
            "no readable source relation" => "没有可读取的来源关系",
            "no result reference supplied" => "未提供结果引用",
            "revision history is not provided for this type" => "此类型未提供修订历史",
            "this payload cannot be edited" => "此内容类型不支持编辑",
            "domain conditions are not satisfied" => "领域操作条件未满足",
            "no eligible forget preview" => "没有可用的遗忘预览",
            "no repository purge preview" => "没有仓库清除预览",
            "not an eligible interrupted attempt" => "不是可操作的中断尝试",
            "no eligible candidate selected" => "未选择可操作的候选",
            "select a recoverybundle" => "请先选择恢复包",
            "read a current snapshot first" => "请先读取当前快照",
            "select a completed backup" => "请选择已完成的备份",
            "select objects in explorer first" => "请先在浏览页选择对象",
            "select an eligible repository" => "请选择可操作的仓库",
            "end of loaded pages" => "已到末页",
            "detail" => "详情",
            "detail [focused]" => "详情［焦点］",
            "loading this page…" => "正在读取当前页…",
            "daemon disconnected; reconnecting" => "本机服务已断开，正在重连",
            "daemon stopping; read unavailable" => "本机服务正在停止，无法读取",
            "no pending items in the visible scope" => "当前可见范围暂无待处理项",
            "no objects in the visible scope; check capture/import in system" => {
                "当前可见范围暂无对象；请到系统页查看采集／导入状态"
            }
            "no tasks on this page" => "当前页没有任务",
            "↑↓ scroll  esc back  / find  : commands" => "↑↓ 滚动  Esc 返回  / 查找  : 命令",
            "↑↓ select  enter detail  tab focus  : commands" => {
                "↑↓ 选择  Enter 详情  Tab 焦点  : 命令"
            }
            "↑↓ select  enter detail  tab/shift+tab focus  : commands" => {
                "↑↓ 选择  Enter 详情  Tab/Shift+Tab 焦点  : 命令"
            }
            "find in loaded body" => "在已加载正文中查找",
            "filter current page" => "筛选当前页",
            "open an item to read its content" => "请选择对象并打开详情以读取内容",
            "task submitted; not yet completed" => "任务已提交，尚未完成",
            "action applied" => "操作已应用",
            "tasks · current page (leased = claimed)" => "任务 · 当前页（已领取不等于正在执行）",
            "tasks · name / state / target / reason" => "任务 · 名称／状态／目标／原因",
            "start/end times not supplied; duration and eta are unknown" => {
                "未提供开始／结束时间，耗时和预计完成时间未知"
            }
            "request sent; result unconfirmed. inspect jobs/results before submitting again" => {
                "请求已发送但结果未确认；再次提交前请先核对任务／结果"
            }
            "edit and accept proposal" => "编辑并接受提议",
            "re-authorize forgotten object" => "重新授权已遗忘对象",
            "submit support replacement" => "提交支持替换",
            "submit support deprecate" => "提交支持弃用",
            "select competing attempt" => "选择竞争尝试",
            "forget object" => "遗忘对象",
            "purge repository" => "清除仓库",
            "verify and enable repository" => "验证并启用仓库",
            "rescan repository capabilities" => "重新扫描仓库能力",
            "create quiesced backup" => "创建静默备份",
            "collect orphan CAS (24 h grace) and prune versions older than 30 d" => {
                "回收孤立 CAS（宽限 24 小时）并清理超过 30 天的版本"
            }
            "verify backup" => "验证备份",
            "unavailable action" => "不可用操作",
            "Content access denied; source or repository restriction" => {
                "正文不可读取：来源或仓库存在访问限制"
            }
            "Exact revision is missing; current revision was not substituted" => {
                "精确修订不存在；未用当前修订代替"
            }
            "Readable content is not supported for this object" => "此对象类型不支持可读正文",
            "Content read could not finish within the bounded access check" => {
                "有界访问检查未能完成正文读取"
            }
            "Content missing from response" => "响应未提供正文",
            "Goals" => "目标",
            "Targets" => "目标对象",
            "Signals" => "信号",
            "Requires" => "需要条件",
            "Excludes" => "排除条件",
            "Do" => "执行步骤",
            "Avoid" => "避免",
            "Done / success" => "完成／成功",
            "Done / abort" => "完成／中止",
            "Done / verify" => "完成／验证",
            "Pitfalls" => "易错点",
            "Exact proposal base" => "提议的精确原版本",
            "Agent-organized plan, not execution or user authorization" => {
                "由代理整理的计划，不代表已执行或获得用户授权"
            }
            "Change: Create — new object, no base" => "变更：新增对象，没有原版本",
            "Original revision could not be read; comparison is incomplete. Existing actions remain governed by the daemon." => {
                "无法读取原版本，比较不完整；操作仍由服务端现有规则判断"
            }
            "Change: exact base → candidate; unchanged fields omitted" => {
                "变更：精确原版本 → 候选；省略未变字段"
            }
            "Known impact: a new revision if applied; impact counts not provided, not estimated" => {
                "已知影响：应用后产生新修订；未提供影响数量，不作估算"
            }
            "allowed by current daemon review" => "当前服务端复核允许",
            "blocked by existing eligibility conditions" => "现有资格条件阻止",
            "not eligible" => "不具备资格",
            "Terminal too small; enlarge the window. Content and edits are retained. Esc back; : commands; ? help" => {
                "终端过小，请扩大窗口；内容与编辑已保留。Esc 返回；: 命令；? 帮助"
            }
            "This page: no task result references" => "本页没有任务结果引用",
            "This page results:" => "本页结果：",
            "Help: Tab/Shift+Tab focus; arrows navigate" => {
                "帮助：Tab/Shift+Tab 切换焦点；方向键导航"
            }
            "[Back / close] Esc" => "[返回／关闭] Esc",
            "not read" => "未读取",
            "Hook: not observed" => "钩子：未观测",
            "not checked" => "未检查",
            "Projection watermarks: not read" => "投影水位：未读取",
            "Selected diagnostic is no longer available; Esc returns" => {
                "所选诊断已不可用；Esc 返回"
            }
            "Diagnostic detail" => "诊断详情",
            "Diagnostics not yet read" => "诊断尚未读取",
            "Metadata is not content verification; terminal failures are history." => {
                "元数据不是内容验证；已结束任务的失败属于历史记录。"
            }
            "Metadata does not verify content integrity; no repair or provider probe is performed." => {
                "元数据不证明内容完整性；本页不会执行修复或模型探测。"
            }
            "Kind" => "类型",
            "Epistemic status" => "认知状态",
            "Text" => "正文",
            "Subject" => "主体",
            "Predicate" => "关系",
            "Object" => "对象",
            "Scope" => "范围",
            "Applicability" => "适用条件",
            "Validity" => "有效期",
            "Avoid condition" => "避免条件",
            "Completion condition" => "完成条件",
            "Branches" => "分支",
            "Abort" => "中止",
            "Verify" => "验证",
            "Title" => "标题",
            "Summary" => "摘要",
            "When / stage" => "适用时机／阶段",
            "Done" => "完成",
            "New field (no base)" => "新增字段（没有原版本）",
            "Original value unavailable" => "原值不可用",
            "Atom revision" => "条目修订",
            "Conflict left atom revision" => "冲突左侧条目修订",
            "Conflict right atom revision" => "冲突右侧条目修订",
            "Scope identity" => "范围身份",
            "Conflict pair is the requested resolution input, not an inferred winning revision" => {
                "冲突对是待解决输入，不代表推测的胜出修订"
            }
            "Open detail" => "查看详情",
            "Type (current page)" => "类型（当前页）",
            "Scope (current page)" => "范围（当前页）",
            "State (current page)" => "状态（当前页）",
            "Content" => "内容",
            "Technical fields" => "技术字段",
            "Sources" => "来源",
            "Open task result" => "查看任务结果",
            "Open sources / dependencies" => "查看来源／依赖",
            "Revision history" => "修订历史",
            "Select / unselect for export" => "加入／移出导出选择",
            "Accept proposal" => "接受提议",
            "Merge and accept" => "合并并接受",
            "Defer proposal" => "延后提议",
            "Reject proposal" => "拒绝提议",
            "Edit and accept" => "编辑并接受",
            "Submit replacement" => "提交替换提议",
            "Submit deprecation" => "提交弃用提议",
            "Resolve as ineffective" => "标记为无效",
            "Dismiss attribution" => "驳回归因",
            "Confirm harm" => "确认有害",
            "Request revision" => "请求修订",
            "Forget object (preview)" => "遗忘对象（预览）",
            "Purge repository (preview)" => "清除仓库（预览）",
            "Mark new attempt" => "标记新尝试",
            "Choose competing attempt" => "选择竞争尝试",
            "Previous competing candidate" => "上个竞争候选",
            "Next competing candidate" => "下个竞争候选",
            "Recover patch" => "恢复补丁",
            "Recover files" => "恢复文件",
            "Recover index" => "恢复索引",
            "Recover mixed" => "混合恢复",
            "First result on this page" => "本页第一个结果",
            "Second result on this page" => "本页第二个结果",
            "Third result on this page" => "本页第三个结果",
            "Overview" => "概览",
            "Jobs" => "任务",
            "Capture and diagnostics" => "采集与诊断",
            "Configuration" => "配置",
            "Maintenance" => "维护",
            "Edit configuration" => "编辑配置",
            "Submit backup job" => "提交备份任务",
            "Submit backup verification" => "提交备份验证",
            "Submit orphan GC" => "提交孤立文件回收",
            "Export selected objects" => "导出选中对象",
            "Restore (offline instructions)" => "恢复（离线说明）",
            "Enable repository" => "启用仓库",
            "Disable repository" => "停用仓库",
            "Rescan repository" => "重新扫描仓库",
            "Filter / find loaded content" => "筛选／查找已加载内容",
            "Clear filter / find" => "清除筛选／查找",
            "Previous match" => "上个匹配",
            "Next match" => "下个匹配",
            "Zoom / restore current area" => "展开／还原当前区域",
            "First page" => "首页",
            "Refresh" => "刷新",
            "Back" => "返回",
            "Inbox" => "待处理",
            "Explorer" => "浏览",
            "System" => "系统",
            "Commands" => "命令",
            "Help" => "帮助",
            "Quit" => "退出",
            "Next page" => "下一页",
            "Select a matching item" => "请先选择匹配项",
            "No supported source relation" => "此类型未提供可读取的来源关系",
            "No readable source relation" => "没有可读取的来源关系",
            "No result reference supplied" => "未提供结果引用",
            "Revision history is not provided for this type" => "此类型未提供修订历史",
            "This payload cannot be edited" => "此内容类型不支持编辑",
            "Domain conditions are not satisfied" => "领域操作条件未满足",
            "No eligible Forget preview" => "没有可用的遗忘预览",
            "No repository purge preview" => "没有仓库清除预览",
            "Not an eligible interrupted attempt" => "不是可操作的中断尝试",
            "No eligible candidate selected" => "未选择可操作的候选",
            "Select a RecoveryBundle" => "请先选择恢复包",
            "Read a current snapshot first" => "请先读取当前快照",
            "Select a completed backup" => "请选择已完成的备份",
            "Select objects in Explorer first" => "请先在浏览页选择对象",
            "Select an eligible repository" => "请选择可操作的仓库",
            "End of loaded pages" => "已到末页",
            "Detail" => "详情",
            "Detail [focused]" => "详情［焦点］",
            "Loading this page…" => "正在读取当前页…",
            "Daemon disconnected; reconnecting" => "本机服务已断开，正在重连",
            "Daemon stopping; read unavailable" => "本机服务正在停止，无法读取",
            "No pending items in the visible scope" => "当前可见范围暂无待处理项",
            "No objects in the visible scope; check capture/import in System" => {
                "当前可见范围暂无对象；请到系统页查看采集／导入状态"
            }
            "No tasks on this page" => "当前页没有任务",
            "not supplied" => "未提供",
            "not yet read" => "尚未读取",
            "page not loaded" => "页面尚未加载",
            " | refreshing" => " | 刷新中",
            "↑↓ scroll  Esc back  / find  : commands" => "↑↓ 滚动  Esc 返回  / 查找  : 命令",
            "↑↓ select  Enter detail  Tab focus  : commands" => {
                "↑↓ 选择  Enter 详情  Tab 焦点  : 命令"
            }
            "↑↓ select  Enter detail  Tab/Shift+Tab focus  : commands" => {
                "↑↓ 选择  Enter 详情  Tab/Shift+Tab 焦点  : 命令"
            }
            "Find in loaded body" => "在已加载正文中查找",
            "Filter current page" => "筛选当前页",
            "Open an item to read its content" => "请选择对象并打开详情以读取内容",
            "Task submitted; not yet completed" => "任务已提交，尚未完成",
            "Action applied" => "操作已应用",
            "Tasks · current page (leased = claimed)" => "任务 · 当前页（已领取不等于正在执行）",
            "Tasks · name / state / target / reason" => "任务 · 名称／状态／目标／原因",
            "Start/end times not supplied; duration and ETA are unknown" => {
                "未提供开始／结束时间，耗时和预计完成时间未知"
            }
            "Request sent; result unconfirmed. Inspect jobs/results before submitting again" => {
                "请求已发送但结果未确认；再次提交前请先核对任务／结果"
            }
            _ => english,
        }
    }

    pub fn from_locale_values(values: [Option<&str>; 3]) -> Self {
        let value = values
            .into_iter()
            .flatten()
            .find(|v| !v.is_empty())
            .unwrap_or("C");
        let marker = value.split(['_', '-', '.', '@']).next().unwrap_or("");
        if marker.eq_ignore_ascii_case("zh") {
            Self::Chinese
        } else {
            Self::English
        }
    }

    pub(crate) fn environment() -> Self {
        let values = ["LC_ALL", "LC_MESSAGES", "LANG"]
            .map(|key| std::env::var_os(key).map(|value| value.to_string_lossy().into_owned()));
        Self::from_locale_values(values.each_ref().map(|v| v.as_deref()))
    }

    pub(crate) fn text<'a>(self, english: &'a str, chinese: &'a str) -> &'a str {
        match self {
            Self::English => english,
            Self::Chinese => chinese,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Language::{self, *};

    #[test]
    fn locale_precedence_and_language_marker_are_pure() {
        for (values, expected) in [
            ([Some("zh_CN.UTF-8"), Some("en_US"), None], Chinese),
            ([Some(""), Some("zh-TW"), Some("en")], Chinese),
            ([None, None, Some("zh")], Chinese),
            ([Some("C"), None, Some("zh_CN")], English),
            ([Some("POSIX"), None, Some("zh")], English),
            ([Some("unknown"), None, Some("zh")], English),
            ([Some(" "), None, Some("zh")], English),
            ([Some("en_GB.UTF-8"), None, None], English),
            ([None, None, None], English),
        ] {
            assert_eq!(Language::from_locale_values(values), expected);
        }
    }
}
