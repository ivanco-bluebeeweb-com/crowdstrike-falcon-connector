# CrowdStrike Falcon Connector — UI component plan

Источники: `Docs/session-notes/UI_COMPONENT_VOCABULARY.md`, `UI_INTERFACE_STANDARD.md`,
`concepts/panels.md`. Основано на функционале `crowdstrike-falcon-connector`.

## 0. Разница с IDEAL_ONBOARDING.md
Идеал предполагает интерактивный per-scope чеклист и живой индикатор открытых RTR-сессий.
Реализация делает проверку тем же способом, что и другие OAuth2 client-credentials
коннекторы портфеля (Okta, PagerDuty) — `connect_crowdstrike` сам выполняет пробный обмен
токена перед сохранением, форма показывает результат через стандартный error/success путь
`ui.Form`. Список нужных scopes описан текстом (`ui.Markdown`) в help-диалоге, не
интерактивными переключателями (SDK не имеет per-scope toggle привязанного к одной форме).
Индикатор активных RTR-сессий не реализован как отдельный live-виджет — сессии видны через
обычный success-результат `start_rtr_session`.

## 1. Компоненты

| Экран | Примитивы | Почему именно эти |
|---|---|---|
| Sidebar (left, not connected) | `ui.Stack`(v, align="stretch") + `ui.Button`("Как создать API Client?" → help overlay) + `ui.Form`(connect_crowdstrike) с лейблами на каждом `ui.Select`/`ui.Input` | Без карточек, без дублирования инструкций — паттерн Okta/ServiceNow/MuleSoft. Форма растянута на всю ширину сайдбара. |
| Connect form fields | labelled `ui.Select`(region: us-1/us-2/eu-1/us-gov-1, placeholder "Выберите регион Falcon") + labelled `ui.Input`(label, placeholder "Acme SOC") + labelled `ui.Input`(client_id, placeholder "OAuth2 Client ID") + labelled `ui.Input`(client_secret, type="password", placeholder "OAuth2 Client Secret") | Регион — первое поле формы (влияет на весь base URL). Пароль скрыт `type="password"`. |
| Help overlay | `ext.panel(slot="overlay")` + `ui.Markdown`(путь в Falcon Console, список scopes по функциям) | Единственное место с инструкциями подключения — не дублируется в сайдбаре. |
| Sidebar (connected) | `ui.Stack`(v) + `ui.Text`(label + region) + `ui.Divider` + `ui.Button`×5 (Incidents/Detections/Hosts/IOCs/Prevention Policies) + `ui.Button`("App settings") | Плоский список разделов, без карточек, "App settings" всегда последним. |
| Incidents list (center, `center_overlay=True`) | `ui.Header` + `ui.DataTable`(id/state/score/hosts/created, отсортировано по fine_score) + row → detail | Табличный список, отсортированный по риску — аналог PagerDuty incident triage. |
| Detections list | `ui.Header` + `ui.DataTable`(hostname/severity badge/status/tactic/technique/created) + row action `ui.Button`("Update status") | `_sev_badge()` красит severity (critical/high = error, medium = warning) для мгновенного визуального триажа. |
| Hosts list | `ui.Header` + `ui.DataTable`(hostname/platform/os_version/last_seen/status) + row actions `ui.Button`("Contain", variant="destructive", confirm=true) / `ui.Button`("Lift containment") | Containment — самое чувствительное действие коннектора, обязательно с native confirm. |
| IOCs list | `ui.Header` + `ui.DataTable`(type/value/action/description) + `ui.Button`("Add IOC") → form | Табличный список, единообразно с остальными сущностями. |
| Prevention Policies list | `ui.Header` + `ui.DataTable`(name/platform/enabled) + row toggle `ui.Button`("Enable"/"Disable", confirm=true при disable) | Отключение policy — риск для покрытия, требует confirm. |
| App settings (center, `center_overlay=True`, отдельная панель) | `ui.Header` + per-connection `ui.Stack`(h) row: label+region + `ui.Button`("Disconnect", variant="destructive") | Disconnect живёт только тут, не дублируется в сайдбаре. |

## 2. Формы: лейблы, плейсхолдеры, растяжение
Все инпуты — с явными `ui.Text`(variant="caption") лейблами через хелпер `_field()`.
Плейсхолдеры контекстные: "Выберите регион Falcon" для Select, "Acme SOC" для лейбла,
"OAuth2 Client ID" / "OAuth2 Client Secret" для credentials. Контейнер `ui.Form` в
сайдбаре растянут на всю ширину (`align="stretch"` на родительском Stack), содержимое
формы растянуто внутри себя тем же `align="stretch"`.

## 3. Пустое состояние центра
Базовая (non-overlay) center-панель с каноничным текстом "Nothing to show here" до выбора
раздела в сайдбаре — регистрируется отдельно, всегда есть даже когда все overlay-панели
закрыты.
