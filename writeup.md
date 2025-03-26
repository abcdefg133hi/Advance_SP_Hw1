# Q1. Why 基於 Syscall Filtering 的方法會被 ROP 攻擊繞過？

在僅攔截「正常路徑」的系統呼叫時，如果攻擊者能夠利用 **Return-Oriented Programming (ROP)** 技術直接在核心或使用者態湊出一段不依賴 `sys_call_table` 的攻擊程式碼，就可以完全繞過基於 `sys_call_table` 的任何過濾機制。

---

## 1. 攻擊原理：繞過 `sys_call_table` 的 Hook

1. **Hook 只攔截「正常流程」的系統呼叫**  
   你的方法是透過修改 `.rodata` 權限，將 `sys_call_table` 對應的 handler 改成自定義的過濾函式，以檢查 `current->comm` 等條件。  
   然而，**ROP 攻擊**並不一定會經由 `sys_call_table` 正常進入核心流程，而是利用程式或核心中現有的 **gadget**（小段指令），再透過對堆疊（或返回位址）的操控來拼湊並執行任意程式邏輯。  
   也就是說，即使你 hook 了系統呼叫入口，只要攻擊者能在 **核心態** 或 **使用者態** 湊出一段 gadget 執行 `syscall` 指令（或直接呼叫核心函式），就能繞過你自定義的攔截邏輯。

2. **ROP 可直接呼叫被過濾的核心函式**  
   在更高權限的攻擊 scenario（例如已取得 kernel-level RCE），可直接在 ROP 中串接核心函式呼叫，根本不需要透過被 hook 的 `sys_call_table`，自然跳過檢查。  
   一旦成功運行這些核心函式，就能完成惡意行為（如對檔案進行 `write`、`mkdir` 等）。

---

## 2. 具體攻擊範例

假設你試圖阻擋一隻惡意程式呼叫 `write` 系統呼叫，以防止寫檔：

1. 使用者以正常方式呼叫 `write()` → 進入你自定義的 handler → 被你根據 `current->comm` 攔截並返回 `-EPERM`。  
2. **攻擊者透過 ROP**：  
   - 在程式或函式庫中尋找可用的 **gadget**。  
   - 將所需參數（檔案描述符、buffer、長度等）準備好。  
   - 利用控制返回位址的能力「拼湊」出一個可直接執行 `syscall` 指令的 gadget（或在核心態直接呼叫底層 `vfs_write()` 等函式）。  
   - 系統最終執行該呼叫並完成檔案寫入，完全繞過你在 `sys_call_table` 內部的攔截。

---

## 3. 如何降低或解決這類弱點

1. **控制流程完整性（Control Flow Integrity, CFI）**  
   - 使用編譯器和硬體輔助的保護機制（如 LLVM CFI、Intel CET、ARM Pointer Authentication 等），在執行時驗證函式跳轉與返回位址的正確性，讓攻擊者難以拼湊 ROP chain。  

2. **強化核心空間的位址隨機化與防洩漏**  
   - 利用 **KASLR (Kernel Address Space Layout Randomization)** 並確保資訊洩漏風險降至最低，使攻擊者難以得知內核中的可用 gadget 位址。  
   - 即使不能防止所有攻擊，也能提高 ROP 成功的難度。

3. **採用更成熟的安全框架或替代方案**  
   - 建議使用 **LSM (Linux Security Module)** 或 **eBPF** 來攔截和過濾系統呼叫；它們在社群與內核層面都有較好的安全維護與檢驗。  
   - 若要自行實作 Hook 方案，也可搭配 eBPF（`kprobe + BPF`）進行更細緻的檢查，而非單純改 `sys_call_table`。

4. **限制對危險函式的存取與保護內核修改**  
   - 你需要透過 `kallsyms_lookup_name()` 與 `update_mapping_prot()` 改寫 `.rodata` 權限才能修改 `sys_call_table`，這本身就是高風險行為。  
   - 建議在「受信任的除錯環境」下使用，並且確保這些高權限 API 不能被惡意程式或模組濫用。

---

## 4. 總結

你的 syscall filtering 架構可以在多數 **正常執行路徑** 中攔截系統呼叫，但當面對 **ROP 攻擊**或其他非常規手段時，就顯得無能為力。要真正避免 ROP 所帶來的威脅，需要進一步強化 **控制流程完整性**、運用 **硬體輔助安全功能**、降低 **位址資訊洩漏**，或乾脆使用 **LSM/eBPF** 等相對成熟的安全機制，才能在核心層面抵禦更進階的攻擊手法。




# 具體範例：如何利用 ROP 直接呼叫核心函式，繞過 `sys_call_table` Hook

以下以 **攔截 `sys_write`** 為例，示範攻擊者如何在擁有核心態（或能影響核心堆疊）的情境下，利用現有的 **gadget**（小段可重複利用的指令片段）直接呼叫內核函式來「手工」完成原本被過濾的行為。此示例可以套用在其它被 hook 的 syscall（如 `mkdirat`、`read` 等）上，核心概念相同。

---

## 1. 預設情況：有一個自訂的 `sys_write` Hook

假設在 `sys_call_table` 裡，你已經用自訂函式取代了原本的 `sys_write`：

1. 使用者態程式以「正常方式」呼叫 `write()` → 進入自訂的 `hooked_sys_write` →  
2. 依照條件（如 `current->comm`）判斷是否攔截 → 若在黑名單就回傳 `-EPERM`。

如此一來，若攻擊者只是單純呼叫 libc 的 `write()`，就會被我們攔截到。

---

## 2. ROP 攻擊繞過 Hook 的概念

**關鍵在於：** `sys_call_table` 裡的 hook 只會攔截「經由該入口函式（`sys_write`）進到核心」的路徑。如果攻擊者能直接在核心態湊出一段 ROP chain，呼叫到「更底層」的寫檔函式（例如 `vfs_write()` 或與之等效的函式）而**不**透過 `sys_call_table`，那麼整個過濾流程就會被繞過。

在某些攻擊場景（如攻擊者已透過 Kernel Exploit 拿到核心態 RCE，或找到了足以控制核心返回位址的漏洞），便能藉由以下步驟完成 ROP 攻擊：

1. **搜尋 Gadget**：  
   - 例如能改動通用暫存器的 `pop rdi; ret`、`pop rsi; ret`、`pop rdx; ret` 等。  
   - 最後能呼叫任意函式的 gadget，例如 `mov rax, [some_addr]; call rax; ret`。

2. **控制堆疊（或返回位址）**：  
   - 使程式返回時不會回到原本的 caller，而是依序執行攻擊者指定的 gadget chain。

3. **湊齊參數並呼叫底層函式**：  
   - 將 `file*`、`buffer`、`size` 等參數塞到對應暫存器（或堆疊），呼叫 `vfs_write()` 或 `__kernel_write()` 等核心內部函式。  
   - 由於沒有透過 `sys_call_table` 的 `sys_write`，所以你的 hook 絕不會被觸發。

---

## 3. 具體 ROP Chain 範例

假設以下是 64-bit Linux Kernel 上找到的幾個關鍵 gadget（其位址只是示意）：

1. `0xffffffff81012345: pop rdi; ret;`  
2. `0xffffffff81012350: pop rsi; ret;`  
3. `0xffffffff81012355: pop rdx; ret;`  
4. `0xffffffff81012360: mov rax, [rip+0xAA]; call rax; ret;`  
   - 其中 `[rip+0xAA]` 裝著 **`vfs_write()` 函式的位址**。

我們想直接呼叫 `vfs_write(file, buffer, size);`

**ROP chain**（示意堆疊內容）：

| Return Address (一次 ret 會跳到哪裡) | 動作                                                     |
| ------------------------------------ | -------------------------------------------------------- |
| 0xffffffff81012345                   | `pop rdi; ret` → 由攻擊者控制，將 `file` 指標塞進 RDI。   |
| (file 指標)                           | 做為上一個 gadget 的數值，由 `pop rdi` 讀入 RDI。         |
| 0xffffffff81012350                   | `pop rsi; ret` → 將 `buffer` 位址塞進 RSI。              |
| (buffer 指標)                         | 做為上一個 gadget 的數值，由 `pop rsi` 讀入 RSI。         |
| 0xffffffff81012355                   | `pop rdx; ret` → 將 `size` 塞進 RDX。                    |
| (size 數值)                           | 做為上一個 gadget 的數值，由 `pop rdx` 讀入 RDX。         |
| 0xffffffff81012360                   | `mov rax, [rip+0xAA]; call rax; ret`                     |
| (可能還有其它輔助數值)               | 內含 `vfs_write` 的位址，最後 `call rax` → 執行 `vfs_write(file, buffer, size)` |

執行到最後一步時，**核心直接進入 `vfs_write()`**，完成寫檔操作；整個過程**不**走 `sys_write` → `hooked_sys_write` 這條路，自然也**不**會被你的自訂過濾器攔截。

---

## 4. 為什麼這能繞過 `sys_call_table` Hook？

- **正常情況**：若使用者要執行系統呼叫，會透過 `syscall` 指令進入 `sys_write`，而你剛好在 `sys_call_table` 替換了該入口函式，所以能攔截。  
- **ROP 攻擊情況**：攻擊者在核心態下，直接以函式呼叫的方式（或透過 gadget chain）把參數塞進對應暫存器後，直接跳到更底層的「最終邏輯」函式（如 `vfs_write()`）。此路徑根本不會再查表或執行 `sys_write`，等於完全繞開了 `sys_call_table` 裏你設下的「檢查哨」。

---

## 5. 延伸：其它繞過方式

1. **不同系統呼叫入口**  
   - 例如在 x86 架構下，除了 64-bit syscall 也可能有 legacy `int 0x80` 或 `sysenter` 的入口；如果你的 hook 只攔截了 64-bit 的 `syscall` entry，就可能被 legacy path 繞過（視核心版本與配置而定）。

2. **直接呼叫核心內部流程**  
   - 不限於 `vfs_write()`，攻擊者也能呼叫 `do_mkdirat()`、`do_sys_open()` 等更底層 API，只要能找到足夠的 gadget 湊出正確參數。

---

## 6. 總結

- **核心精神**：只要攻擊者可以在核心態任意控制程式流程，便能拼湊出「自訂函式呼叫」，完全不經過你在 `sys_call_table` 裏頭注入的 Hook。  
- **示範 ROP Chain**：以攔截 `sys_write` 為例，透過一連串 `pop rdi; ret`、`pop rsi; ret` 等 gadget，最後「call `vfs_write`」即可完成寫檔，系統並不會經過你攔截的 `sys_write`。  

這正是 **Return-Oriented Programming** 攻擊能繞過「僅在 syscall table 進行攔截」的重要原因，也是為什麼我們需要控制流程完整性（CFI）、ASLR/KASLR 等更深入的防護機制來抵擋高階攻擊手法。





# Q2. Comparison: Syscall Table Hooking vs. `ptrace`-Based Approach

以下是本次作業中利用 **Hook `sys_call_table`** 做系統呼叫過濾的優缺點，與使用 **`ptrace`** 監控行為的方式相比的分析。

---

## 1. Syscall Table Hooking Approach

### 優點
1. **直接在 Kernel 層攔截**  
   - 相較於 `ptrace`（通常在使用者態運作），直接在核心態攔截更不易被使用者態程式避開，也能更有效地攔截所有透過正常系統呼叫路徑進入內核的行為。

2. **執行效率高**  
   - 攔截與檢查過程在內核中進行，不需每次都在使用者態與核心態之間進行頻繁的切換，減少了上下文切換的開銷。

3. **可進行更底層、更細緻的控制**  
   - 在內核層能夠檢查與控制的資訊更多，如對呼叫參數、Process Context（`current->comm` 等）做直接存取與判斷。

### 缺點
1. **相容性與維護困難**  
   - 需要修改（或至少動態重排）核心的只讀區段（`.rodata`），對不同版本的 Linux 內核及其安全保護機制（如`CONFIG_STRICT_KERNEL_RWX`）易產生相容性問題，也可能在系統更新後破壞穩定性。

2. **侵入性高、風險大**  
   - 直接修改 `sys_call_table` 屬於高風險操作，可能引入安全漏洞或導致非預期的系統行為；若實作不當更可能引發系統崩潰（kernel panic）。

3. **保護機制與逆向對抗**  
   - 內核在持續加強針對 `sys_call_table` 與符號表的保護，不斷有新的限制與修補手段；實際部署時可能需要額外繞過 KASLR、嚴格的符號匯出限制等。

---

## 2. `ptrace`-Based Approach

### 優點
1. **實作與維護難度相對較低**  
   - `ptrace` 是使用者態 API，不需直接修改內核結構或 `.rodata` 權限；在使用者態即可啟動對目標程序的系統呼叫監控。

2. **較好與開發者工具整合**  
   - `ptrace` 機制廣泛應用於調試（如 GDB）、系統分析工具，開發者在 user space 就能方便地實作監控或偵錯邏輯。

3. **影響範圍可控**  
   - 因為是針對特定程序進行追蹤與攔截，對系統整體影響較小，也不必冒著改寫核心結構的風險。

### 缺點
1. **效能較差**  
   - 系統呼叫需經過與 `ptrace` 監視程序之間的多次切換，每次 syscall 都會有較高的上下文切換開銷，對系統整體效能影響顯著。

2. **容易被目標程式偵測或干擾**  
   - 目標程式可檢測到自己被 `ptrace`，或透過一些技巧嘗試脫離 `ptrace` 監控（如 `ptrace` 自身反制技術或使用其他 API 進行自我檢查）。

3. **無法監控所有核心層行為**  
   - `ptrace` 主要用於追蹤使用者態進程，對於內核態觸發的行為或更底層的機制不一定能有效攔截。

---

## 3. 總結

**Hook `sys_call_table`** 的方法可更直接地控制內核層的行為、效能也較好，但風險和維護成本高；**`ptrace`** 則能在使用者態以更低的門檻監控指定進程的系統呼叫，但容易帶來較高的效能開銷，而且可監控範圍與安全強度較低。實際選擇何種機制，通常取決於：

- 系統的安全需求與 **可信度** 要求
- **維護與相容性** 考量
- 對 **效能** 與 **開發便利性** 的平衡
