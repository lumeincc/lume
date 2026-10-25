# Code Review Style Guide

This file contains style and formatting rules that a reviewer checks and fixes during review. These are mechanical issues that should always be caught during code review.

---

## TypeScript — строгая типизация

Никогда не использовать `any`. Всегда сужать через type guards или Zod.

```typescript
// BAD
function process(data: any) {
  return data.value
}

// GOOD
function process(data: unknown) {
  if (typeof data === 'object' && data !== null && 'value' in data) {
    return (data as { value: string }).value
  }
}
```

Если тип уже проверен через Zod — используй `z.infer<>`:

```typescript
// BAD
const body = req.body as any

// GOOD
const body = req.body as z.infer<typeof MySchema> // safe: validated by middleware
```

---

## Result Pattern — не бросать исключения в бизнес-логике

Ожидаемые ошибки возвращаются через Result, не через throw.

```typescript
// BAD
function getUser(id: string): User {
  const user = db.getUserById(id)
  if (!user) throw new Error('User not found')
  return user
}

// GOOD
function getUser(id: string): Result<User, 'not_found'> {
  const user = db.getUserById(id)
  if (!user) return { ok: false, error: 'not_found' }
  return { ok: true, data: user }
}
```

---

## Immutability — никогда не мутировать напрямую

```typescript
// BAD
state.messages.push(newMessage)
user.name = 'new name'

// GOOD
const newMessages = [...state.messages, newMessage]
const updatedUser = { ...user, name: 'new name' }
```

В Zustand:

```typescript
// BAD
set(state => { state.count++ })

// GOOD
set(state => ({ count: state.count + 1 }))
```

---

## Zustand — селекторы только по полю

```typescript
// BAD — подписка на весь стор, ре-рендер при любом изменении
const store = useAuthStore()

// GOOD — подписка только на нужное поле
const user = useAuthStore(s => s.user)
const isOnline = useMessengerStore(s => s.isOnline)
```

---

## API вызовы — только из хуков и компонентов, не из сторов

```typescript
// BAD — прямой API вызов из стора
const useAuthStore = create((set) => ({
  login: async (pin: string) => {
    const data = await authApi.login(pin) // ❌
    set({ user: data.user })
  }
}))

// GOOD — API вызов из хука, стор только держит состояние
function useLogin() {
  const setUser = useAuthStore(s => s.setUser)
  return async (pin: string) => {
    const data = await authApi.login(pin) // ✅
    setUser(data.user)
  }
}
```

---

## Валидация ответов сервера перед использованием

```typescript
// BAD — доверяем серверу без проверки
const { data } = await authApi.getUser(id)
setUser(data.user) // может быть undefined

// GOOD — проверяем через Zod
const parsed = UserResponseSchema.safeParse(data)
if (!parsed.success) {
  console.error('Invalid response:', parsed.error.issues[0]?.message)
  return
}
setUser(parsed.data.user)
```

---

## UI — никаких хардкодных px значений в компонентах

```tsx
// BAD — ломается на разных экранах, игнорирует дизайн-систему
<div style={{ margin: 10, padding: 8, fontSize: 14, color: '#fff' }}>

// GOOD — использует дизайн-систему
<div className="m-2 p-2 text-sm text-[var(--text-primary)]">
```

CSS переменные дизайн-системы:
- `var(--bg)` — основной фон
- `var(--surface)` — поверхность карточек
- `var(--border)` — цвет границ
- `var(--text-primary)` — основной текст
- `var(--text-secondary)` — вторичный текст
- `var(--accent)` — акцентный цвет

---

## React — "use client" только когда нужно

```typescript
// BAD — добавляет "use client" везде по умолчанию
"use client"
export function StaticTitle({ text }: { text: string }) {
  return <h1>{text}</h1> // нет хуков, нет событий — не нужен "use client"
}

// GOOD — Server Component по умолчанию
export function StaticTitle({ text }: { text: string }) {
  return <h1>{text}</h1>
}

// "use client" только когда есть хуки, state, или browser API
"use client"
export function Counter() {
  const [count, setCount] = useState(0)
  return <button onClick={() => setCount(c => c + 1)}>{count}</button>
}
```

---

## React — никаких document.querySelector в компонентах

```tsx
// BAD
useEffect(() => {
  const el = document.querySelector('.message-input')
  el?.focus()
}, [])

// GOOD
const inputRef = useRef<HTMLInputElement>(null)
useEffect(() => {
  inputRef.current?.focus()
}, [])
return <input ref={inputRef} />
```

---

## React — никаких setTimeout для UI состояния

```typescript
// BAD — хрупко, зависит от времени
setTimeout(() => setIsVisible(false), 300)

// GOOD — CSS transition + onTransitionEnd или useEffect с cleanup
useEffect(() => {
  if (!isVisible) return
  const timer = setTimeout(() => setIsVisible(false), 300)
  return () => clearTimeout(timer)
}, [isVisible])
```

---

## SQL — только параметризованные запросы

```typescript
// BAD — SQL injection
const query = `SELECT * FROM users WHERE username = '${username}'`

// GOOD — параметризованный prepared statement
const stmt = db.prepare('SELECT * FROM users WHERE username = ?')
const user = stmt.get(username)
```

---

## Роуты — тонкие хендлеры, без бизнес-логики

```typescript
// BAD — бизнес-логика прямо в роуте
router.post('/messages/send', requireSignature, async (req, res) => {
  const { recipientId, payload } = req.body
  const isBlocked = db.isBlocked(recipientId, req.userId)
  if (isBlocked) return res.status(403).json({ error: 'Blocked' })
  const count = db.getPendingMessageCount(recipientId)
  if (count >= 10000) return res.status(507).json({ error: 'Full' })
  const id = crypto.randomUUID()
  db.queueMessage(id, req.userId, recipientId, payload)
  // ...
})

// GOOD — роут делегирует, не содержит логики
router.post('/messages/send',
  requireSignature,
  validateBody(SendMessageSchema),
  messageController.send  // логика в контроллере/сервисе
)
```

---

## Комментарии — только для сложных алгоритмов

Не писать комментарии которые просто описывают следующую строку. Код должен быть самодокументируемым через понятные имена.

```typescript
// BAD — очевидный комментарий
// Get user by id
const user = db.getUserById(userId)

// BAD — описание очевидного действия
// Check if blocked
if (isBlocked) return

// GOOD — комментарий только когда нужно объяснить ПОЧЕМУ, не ЧТО
// PBKDF2 с 100K итерациями намеренно медленный — защита от брутфорса
const key = await crypto.subtle.deriveBits(...)

// GOOD — сложный алгоритм требует объяснения (4+ строки)
// Double Ratchet step: при получении нового DH публичного ключа
// выполняем DH ratchet перед symmetric ratchet.
// Это обеспечивает forward secrecy — компрометация текущего ключа
// не раскрывает предыдущие сообщения.
```

---

## Объединять последовательные ветки с одинаковым телом

```typescript
// BAD — дублированное тело
if (!user) {
  return res.status(404).json({ error: 'Not found' })
}
if (!user.isActive) {
  return res.status(404).json({ error: 'Not found' })
}

// GOOD — объединить условия
if (!user || !user.isActive) {
  return res.status(404).json({ error: 'Not found' })
}
```

---

## Инициализировать переменные базовых типов

```typescript
// BAD — неинициализированные поля
class MessageHandler {
  private count: number
  private isProcessing: boolean
  private lastSender: string | null
}

// GOOD
class MessageHandler {
  private count = 0
  private isProcessing = false
  private lastSender: string | null = null
}
```

---

## Импорты — сортировать по группам

```typescript
// BAD — вперемешку
import { useState } from 'react'
import database from '../db/database'
import { z } from 'zod'
import type { Request } from 'express'
import { validateBody } from '../middleware/validate'

// GOOD — группы: внешние → внутренние → типы
import { useState } from 'react'
import { z } from 'zod'

import database from '../db/database'
import { validateBody } from '../middleware/validate'

import type { Request } from 'express'
```

---

## Обнулять ключевой материал после использования

```typescript
// BAD — ключ остаётся в памяти
const keyBytes = nacl.box.keyPair().secretKey
const encrypted = nacl.box(message, nonce, theirKey, keyBytes)
// keyBytes висит в памяти — риск утечки через heap dump

// GOOD — обнулить сразу после использования
const keyPair = nacl.box.keyPair()
const encrypted = nacl.box(message, nonce, theirKey, keyPair.secretKey)
keyPair.secretKey.fill(0) // обнулить
```

---

## Сравнение секретов — только через timingSafeEqual

```typescript
// BAD — timing attack
if (token === expectedToken) {

// GOOD — постоянное время сравнения
import { timingSafeEqual } from 'crypto'
const a = Buffer.from(token)
const b = Buffer.from(expectedToken)
if (a.length === b.length && timingSafeEqual(a, b)) {
```

---

## Связанные useState — объединять в один объект

Несколько `useState`, которые меняются вместе, — это одно состояние, разложенное по переменным. Они рассинхронизируются, и каждый `set` даёт отдельный ре-рендер.

```typescript
// BAD — четыре стейта, которые всегда меняются вместе
const [sending, setSending] = useState(false)
const [error, setError] = useState<string | null>(null)
const [progress, setProgress] = useState(0)
const [attachmentId, setAttachmentId] = useState<string | null>(null)

// сброс приходится делать в четыре вызова, и легко забыть один
setSending(false)
setError(null)
setProgress(0)
// setAttachmentId забыли — остался от прошлой отправки
```

```typescript
// GOOD — одно состояние, один переход
type UploadState =
  | { status: 'idle' }
  | { status: 'sending'; progress: number; attachmentId: string }
  | { status: 'failed'; error: string }

const [upload, setUpload] = useState<UploadState>({ status: 'idle' })

setUpload({ status: 'idle' }) // невозможно сбросить наполовину
```

Размеченное объединение здесь даёт больше, чем просто объект: невалидные комбинации (`sending: false` вместе с `progress: 42`) перестают существовать на уровне типа.

Не объединять состояния, которые меняются независимо, — это уже связывание без причины.

---

## Выносить существенную логику из инлайн-стрелок

Обработчик в JSX должен читаться как намерение, а не как реализация. Тело длиннее пары строк — выносим и называем.

```typescript
// BAD — логика похоронена в разметке
<button
  onClick={() => {
    const trimmed = draft.trim()
    if (!trimmed) return
    const optimistic = { id: nanoid(), body: trimmed, status: 'pending' as const }
    setMessages(prev => [...prev, optimistic])
    setDraft('')
    void sendMessage(chatId, trimmed).catch(() => {
      setMessages(prev =>
        prev.map(m => (m.id === optimistic.id ? { ...m, status: 'failed' } : m)),
      )
    })
  }}
>
  Send
</button>
```

```typescript
// GOOD — намерение в разметке, реализация рядом
const handleSend = useCallback(async () => {
  const trimmed = draft.trim()
  if (!trimmed) return
  // ...
}, [draft, chatId])

<button onClick={() => void handleSend()}>Send</button>
```

Короткие стрелки (`onClick={() => setOpen(false)}`) выносить не надо — правило про существенную логику, а не про любую.

---

## Таблица соответствий вместо цепочки if/else

Когда ветки различаются только данными, цепочка условий прячет это за управляющей конструкцией. Таблица делает набор случаев видимым и заставляет TypeScript проверить полноту.

```typescript
// BAD — три ветки, отличающиеся только текстом и иконкой
function statusLabel(status: MessageStatus): string {
  if (status === 'pending') return 'Отправляется'
  else if (status === 'sent') return 'Доставлено'
  else if (status === 'read') return 'Прочитано'
  else if (status === 'failed') return 'Не отправлено'
  return ''
}
```

```typescript
// GOOD — данные отдельно, поиск отдельно
const STATUS_LABELS: Record<MessageStatus, string> = {
  pending: 'Отправляется',
  sent: 'Доставлено',
  read: 'Прочитано',
  failed: 'Не отправлено',
}

const statusLabel = (status: MessageStatus): string => STATUS_LABELS[status]
```

Выигрыш не в краткости: `Record<MessageStatus, ...>` не соберётся, если в `MessageStatus` добавят вариант и забудут про него здесь. Цепочка `if` в этом случае молча вернёт `''`.

Если у веток разное поведение, а не разные данные, — цепочка уместна, не надо выкручивать её в таблицу.

---

## Не глушить проверки через `!`

В `tsconfig` включён `noUncheckedIndexedAccess`: доступ по индексу даёт `T | undefined`. Non-null assertion возвращает ровно тот класс ошибок, ради которого флаг включали, — и делает это молча.

```typescript
// BAD — «я точно знаю, что элемент есть»
const first = messages[0]!
const session = sessions.get(contactId)!
renderBubble(first.body)
```

```typescript
// GOOD — проверить и обработать отсутствие
const first = messages[0]
if (!first) return null

const session = sessions.get(contactId)
if (!session) {
  return { ok: false, error: 'session_missing' }
}
```

Это же касается `as` поверх неизвестных данных: если значение пришло с сервера или из хранилища, его сужают через Zod, а не утверждением типа.

Исключение — тесты, где отсутствие значения само по себе является провалом теста и `!` короче явной проверки.

---

## Размер шрифта — именованной ступенью, не `text-[Npx]`

Шкала уже сложилась и менять её не нужно — нужно называть её ступени. Каждое соответствие ниже **точное**: замена ничего не двигает на экране.

| Размер | Пишем | Откуда ступень |
|---|---|---|
| 10px | `text-micro` | наш токен |
| 11px | `text-caption` | наш токен |
| 12px | `text-xs` | штатный Tailwind |
| 13px | `text-body` | наш токен |
| 14px | `text-sm` | штатный Tailwind |
| 16px | `text-base` | штатный Tailwind |
| 20px | `text-xl` | штатный Tailwind |
| 22px | `text-display` | наш токен |

```tsx
// BAD — значение вместо ступени
<span className="text-[13px] text-[var(--text-secondary)]">{preview}</span>
<time className="text-[11px]">{time}</time>

// GOOD — ступень шкалы
<span className="text-body text-[var(--text-secondary)]">{preview}</span>
<time className="text-caption">{time}</time>
```

**Штатные ступени Tailwind не переопределять.** `text-xs` уже равен 12px, `text-sm` — 14px, `text-base` — 16px, `text-xl` — 20px. Наши токены закрывают только те шаги, которых у Tailwind нет: 10, 11, 13 и 22. Переопределение `--text-sm` под 12px молча уменьшит 23 места, где `text-sm` уже стоит.

**Значения вне таблицы — не изобретать.** Вне шкалы остались пять мест: `text-[15px]` ×3, `text-[17px]` и `text-[19px]` по одному. Они сохранены намеренно — свести их к соседней ступени значит сдвинуть пиксели, а это решение по дизайну, не по стилю кода. Нужен размер, которого нет в таблице, — это разговор о шкале, а не выбор внутри компонента.
