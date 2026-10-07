/**
 * ARTEX Runtime i18n - Korean Translation
 * 
 * This module provides runtime DOM-based translation from Chinese to Korean.
 * It uses MutationObserver to automatically translate dynamically added content.
 * 
 * Usage: Import and call initI18n() once in the root layout.
 */

const ZH_KO: [RegExp, string][] = [
  // ─── 사이드바/메뉴 (already in sidebar-items.ts, but for dynamic rendering) ───
  [/功能/g, "기능"],
  [/仪表盘/g, "대시보드"],
  [/工具执行/g, "도구 실행"],
  [/工作空间/g, "워크스페이스"],
  [/LLM 录制/g, "LLM 녹화"],
  [/资产同步/g, "자산 동기화"],
  [/资产拦截/g, "자산 차단"],
  [/资产覆盖图/g, "자산 커버리지 맵"],
  [/通知推送/g, "알림"],
  [/拦截规则/g, "차단 규칙"],
  [/拦截审批/g, "차단 승인"],
  [/审批记录/g, "승인 기록"],
  [/系统配置/g, "시스템 설정"],
  [/系统提示词/g, "시스템 프롬프트"],
  [/系统审计/g, "시스템 감사"],
  [/系统事件/g, "시스템 이벤트"],

  // ─── 탭/페이지 제목 ───
  [/测试资产/g, "테스트 자산"],
  [/探索链路/g, "탐색 경로"],
  [/播报板/g, "알림판"],
  [/总览/g, "개요"],
  [/会话列表/g, "세션 목록"],
  [/会话/g, "세션"],
  [/复测计划/g, "재검증 계획"],
  [/复测结果/g, "재검증 결과"],
  [/发起复测/g, "재검증 시작"],
  [/复测/g, "재검증"],
  [/报告/g, "보고서"],

  // ─── 상태 (status.ts already translated but for dynamic text) ───
  [/探索中/g, "탐색 중"],
  [/运行中/g, "실행 중"],
  [/执行中/g, "실행 중"],
  [/已暂停/g, "일시정지"],
  [/已完成/g, "완료"],
  [/已创建/g, "생성됨"],
  [/排队中/g, "대기열"],
  [/已超时/g, "시간 초과"],
  [/执行出错/g, "실행 오류"],
  [/预算耗尽/g, "예산 소진"],
  [/已停止/g, "중지됨"],
  [/已删除/g, "삭제됨"],
  [/进行中/g, "진행 중"],
  [/已达成/g, "달성"],
  [/已放弃/g, "포기"],
  [/已确认/g, "확인됨"],
  [/已处理/g, "처리됨"],
  [/已修复/g, "수정됨"],
  [/待处理/g, "미처리"],
  [/处理中/g, "처리 중"],
  [/待发送/g, "발송 대기"],
  [/发送中/g, "발송 중"],
  [/已送达/g, "발송 완료"],
  [/已跳过/g, "건너뜀"],
  [/空闲/g, "대기"],
  [/停滞/g, "정체"],
  [/待领/g, "대기 중"],
  [/误报/g, "오탐"],
  [/风险接受/g, "위험 수용"],

  // ─── 심각도 ───
  [/严重/g, "심각"],
  [/高危/g, "높음"],
  [/中危/g, "보통"],
  [/低危/g, "낮음"],

  // ─── 감사/차단 ───
  [/放行/g, "허용"],
  [/拦截/g, "차단"],
  [/观测/g, "관측"],
  [/废弃/g, "폐기"],

  // ─── 세션/에이전트 ───
  [/主 Agent/g, "메인 에이전트"],
  [/旁路提问/g, "별도 질문"],
  [/态势研判/g, "상황 분석"],
  [/LLM 故障转移/g, "LLM 장애조치"],
  [/故障转移/g, "장애조치"],
  [/可交互/g, "대화 가능"],
  [/实时流式中/g, "실시간 스트리밍 중"],
  [/实时/g, "실시간"],
  [/给主 Agent 发消息/g, "메인 에이전트에게 메시지 보내기"],
  [/发送消息/g, "메시지 전송"],
  [/停止当前执行/g, "현재 실행 중지"],
  [/上传文件/g, "파일 업로드"],
  [/跟随默认配置/g, "기본 설정 따름"],

  // ─── 작업(task) 관련 ───
  [/当前任务/g, "현재 작업"],
  [/已归档/g, "보관됨"],
  [/新建任务/g, "새 작업"],
  [/并发设置/g, "동시실행 설정"],
  [/分类管理/g, "분류 관리"],
  [/任务模板/g, "작업 템플릿"],
  [/任务分类/g, "작업 분류"],
  [/关联任务/g, "연관 작업"],
  [/高级设置/g, "고급 설정"],
  [/创建时间/g, "생성 시간"],
  [/运行时长/g, "실행 시간"],
  [/暂无任务/g, "작업 없음"],

  // ─── LLM 설정 ───
  [/新建模型配置/g, "새 모델 설정"],
  [/模型配置/g, "모델 설정"],
  [/测试连接/g, "연결 테스트"],
  [/设为激活/g, "활성화"],
  [/已激活/g, "활성화됨"],
  [/每秒限速/g, "초당 제한"],
  [/每分钟限速/g, "분당 제한"],
  [/上下文窗口/g, "컨텍스트 창"],
  [/轮询配置/g, "라운드로빈 설정"],
  [/轮询优先级/g, "라운드로빈 우선순위"],
  [/不参与轮询/g, "라운드로빈 제외"],
  [/重试与退避/g, "재시도 및 백오프"],
  [/流式输出/g, "스트리밍 출력"],
  [/输出上限/g, "출력 상한"],
  [/上限字段名/g, "상한 필드명"],
  [/思考开关/g, "사고 스위치"],
  [/思考强度/g, "사고 강도"],
  [/重试覆盖/g, "재시도 오버라이드"],
  [/建连重试/g, "연결 재시도"],
  [/空响应重试/g, "빈 응답 재시도"],
  [/重试次数/g, "재시도 횟수"],
  [/自定义会话头/g, "커스텀 세션 헤더"],

  // ─── 인증/로그인 ───
  [/初始化密码/g, "초기 비밀번호 설정"],
  [/设置密码并登录/g, "비밀번호 설정 후 로그인"],
  [/确认密码/g, "비밀번호 확인"],
  [/修改密码/g, "비밀번호 변경"],
  [/当前密码/g, "현재 비밀번호"],
  [/新密码/g, "새 비밀번호"],
  [/登录/g, "로그인"],
  [/注销/g, "로그아웃"],
  [/密码/g, "비밀번호"],

  // ─── 시스템 설정 ───
  [/版本与更新/g, "버전 및 업데이트"],
  [/一键更新/g, "원클릭 업데이트"],
  [/全局代理/g, "글로벌 프록시"],
  [/检查更新/g, "업데이트 확인"],
  [/回滚到上一版本/g, "이전 버전으로 롤백"],

  // ─── 자산 관련 ───
  [/企业资产范围/g, "기업 자산 범위"],
  [/资产范围/g, "자산 범위"],
  [/域名/g, "도메인"],
  [/子域/g, "서브도메인"],
  [/端口/g, "포트"],
  [/站点/g, "사이트"],
  [/端点/g, "엔드포인트"],
  [/企业/g, "기업"],

  // ─── 알림 ───
  [/推送通道/g, "알림 채널"],
  [/投递记录/g, "전송 기록"],
  [/汇总/g, "요약"],

  // ─── 공통 동사/버튼 ───
  [/暂停/g, "일시정지"],
  [/恢复/g, "재개"],
  [/继续/g, "계속"],
  [/删除/g, "삭제"],
  [/新建/g, "새로 만들기"],
  [/编辑/g, "편집"],
  [/保存/g, "저장"],
  [/取消/g, "취소"],
  [/确定/g, "확인"],
  [/确认/g, "확인"],
  [/提交/g, "제출"],
  [/搜索/g, "검색"],
  [/刷新/g, "새로고침"],
  [/关闭/g, "닫기"],
  [/返回/g, "돌아가기"],
  [/上传/g, "업로드"],
  [/下载/g, "다운로드"],
  [/导出/g, "내보내기"],
  [/导入/g, "가져오기"],
  [/复制/g, "복사"],
  [/重试/g, "재시도"],
  [/加载中/g, "로딩 중"],
  [/操作/g, "작업"],

  // ─── 공통 명사/라벨 ───
  [/名称/g, "이름"],
  [/描述/g, "설명"],
  [/目标/g, "목표"],
  [/状态/g, "상태"],
  [/类型/g, "유형"],
  [/版本/g, "버전"],
  [/配置/g, "설정"],
  [/模型/g, "모델"],
  [/格式/g, "형식"],
  [/代理/g, "프록시"],
  [/触发器/g, "트리거"],
  [/可见性/g, "가시성"],
  [/服务/g, "서비스"],
  [/节点/g, "노드"],
  [/今日/g, "오늘"],
  [/本周/g, "이번 주"],
  [/本月/g, "이번 달"],
  [/总计/g, "합계"],
  [/活动/g, "활동"],
  [/消耗/g, "소비"],

  // ─── 기타/데이터 표시 ───
  [/暂无数据/g, "데이터 없음"],
  [/已选择/g, "선택됨"],
  [/全部/g, "전체"],
  [/筛选/g, "필터"],
  [/排序/g, "정렬"],
  [/升序/g, "오름차순"],
  [/降序/g, "내림차순"],
  [/失败/g, "실패"],
  [/成功/g, "성공"],
  [/正常/g, "정상"],
  [/系统/g, "시스템"],
  [/对话/g, "대화"],
  [/任务/g, "작업"],
  [/发现/g, "발견"],
  [/流量/g, "트래픽"],
  [/资产/g, "자산"],
  [/日志/g, "로그"],
  [/工具/g, "도구"],
  [/设置/g, "설정"],
  [/规则/g, "규칙"],
  [/审批/g, "승인"],
  [/通知/g, "알림"],
  [/记录/g, "기록"],
  [/管理/g, "관리"],
  [/创建/g, "생성"],
  [/更新/g, "업데이트"],
  [/选择/g, "선택"],
  [/条\/页/g, "건/페이지"],
  [/条/g, "건"],
  [/个/g, "개"],
  [/共/g, "총"],
  [/页/g, "페이지"],
];

function translateText(text: string): string {
  let result = text;
  for (const [pattern, replacement] of ZH_KO) {
    result = result.replace(pattern, replacement);
  }
  return result;
}

function translateNode(node: Node): void {
  if (node.nodeType === Node.TEXT_NODE) {
    const original = node.textContent ?? "";
    // Only process if contains Chinese characters
    if (/[\u4e00-\u9fff]/.test(original)) {
      const translated = translateText(original);
      if (translated !== original) {
        node.textContent = translated;
      }
    }
  } else if (node.nodeType === Node.ELEMENT_NODE) {
    const el = node as HTMLElement;
    // Translate placeholder
    if (el.getAttribute("placeholder") && /[\u4e00-\u9fff]/.test(el.getAttribute("placeholder")!)) {
      el.setAttribute("placeholder", translateText(el.getAttribute("placeholder")!));
    }
    // Translate title
    if (el.title && /[\u4e00-\u9fff]/.test(el.title)) {
      el.title = translateText(el.title);
    }
    // Translate aria-label
    const ariaLabel = el.getAttribute("aria-label");
    if (ariaLabel && /[\u4e00-\u9fff]/.test(ariaLabel)) {
      el.setAttribute("aria-label", translateText(ariaLabel));
    }
    // Recurse children
    for (const child of Array.from(node.childNodes)) {
      translateNode(child);
    }
  }
}

let observer: MutationObserver | null = null;

export function initI18n(): void {
  if (typeof window === "undefined") return;
  if (observer) return; // already initialized

  // Initial pass
  translateNode(document.body);

  // Watch for dynamic changes
  observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const added of Array.from(mutation.addedNodes)) {
        translateNode(added);
      }
      if (mutation.type === "characterData" && mutation.target.textContent) {
        translateNode(mutation.target);
      }
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
    characterData: true,
  });
}

export function destroyI18n(): void {
  observer?.disconnect();
  observer = null;
}
