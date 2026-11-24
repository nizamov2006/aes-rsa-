'use strict';

const byId = id => document.getElementById(id);
const alphabetCards = Array.from(document.querySelectorAll('.abp'));
let alphabet = '';
let installPrompt;

const models = {
  aes: [
    ['AES кілті', 'K = SHA-256(сандық кілт)[0…15]'],
    ['Есептегіш', 'Бастапқы есептегіш = 0 (16 байт)'],
    ['AES ағыны', 'S = AES-CTR(K, 0)'],
    ['Әріптің индексі', 'Mᵢ = таңдалған әліпбидегі индекс'],
    ['Байтты түрлендіру', 'Xᵢ = Mᵢ ⊕ Sᵢ'],
    ['RSA модулі', 'n = 17 × 19 = 323'],
    ['Эйлер функциясы', 'φ(n) = 16 × 18 = 288'],
    ['Ашық көрсеткіш', 'e = 5'],
    ['Жабық көрсеткіш', 'd = 173, өйткені 5 × 173 ≡ 1 (mod 288)'],
    ['RSA шифрлау', 'Rᵢ = Xᵢ⁵ mod 323'],
    ['RSA кері шифрлау', 'Xᵢ = Rᵢ¹⁷³ mod 323'],
    ['Мәтінді қалпына келтіру', 'Mᵢ = Xᵢ ⊕ Sᵢ']
  ],
  vig: [
    ['Шифрлау', 'Cᵢ = (Mᵢ + K[i mod n]) mod N'],
    ['Әліпби', 'N = таңдалған әліпбидегі әріп саны'],
    ['Әріп индексі', 'Mᵢ = ашық мәтіндегі әріптің индексі'],
    ['Кілт', 'n = кілттің ұзындығы, Kᵢ ∈ {0,…,9}'],
    ['Кілтті қайталау', 'Kᵢ = K[i mod n]'],
    ['Модуль бойынша қосу', 'Мысалы, (41 + 4) mod 42 = 3'],
    ['Кері шифрлау', 'Mᵢ = (Cᵢ − Kᵢ + N) mod N'],
    ['Басқа таңбалар', 'Бос орын мен тыныс белгілері сол күйінде қалады']
  ]
};

function modPow(base, exponent) {
  let result = 1;
  while (exponent > 0) {
    if (exponent % 2) result = (result * base) % 323;
    base = (base * base) % 323;
    exponent = Math.floor(exponent / 2);
  }
  return result;
}

async function aesStream(key, length) {
  if (!globalThis.crypto?.subtle) throw new Error('AES үшін HTTPS немесе localhost арқылы ашыңыз.');
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key));
  const aesKey = await crypto.subtle.importKey('raw', hash.slice(0, 16), 'AES-CTR', false, ['encrypt']);
  return new Uint8Array(await crypto.subtle.encrypt(
    {name: 'AES-CTR', counter: new Uint8Array(16), length: 128},
    aesKey, new Uint8Array(length)
  ));
}

async function calculate(prefix, input, key, decrypt, letters) {
  const rows = [];
  if (prefix === 'vig') {
    const output = Array.from(input, char => {
      const index = letters.indexOf(char.toUpperCase());
      if (index < 0) return char;
      const shift = Number(key[rows.length % key.length]);
      const next = (index + (decrypt ? -shift : shift) + letters.length) % letters.length;
      const result = char === char.toUpperCase() ? letters[next] : letters[next].toLowerCase();
      rows.push({value: next, cells: [char + ' · ' + index, shift,
        '(' + index + (decrypt ? ' − ' : ' + ') + shift + ') mod ' + letters.length + ' = ' + next, result]});
      return result;
    }).join('');
    return {output, rows};
  }

  let values;
  if (decrypt) {
    const tokens = input.trim().split(/\s+/);
    if (tokens.some(token => !/^\d{1,3}$/.test(token) || Number(token) >= 323)) {
      throw new Error('Шифрмәтінді 0–322 аралығындағы сандармен енгізіңіз. Сандарды бос орынмен бөліңіз.');
    }
    values = tokens.map(Number);
  } else {
    const chars = Array.from(input.toUpperCase()).filter(char => !/\s/.test(char));
    values = chars.map(char => letters.indexOf(char));
    if (values.some(index => index < 0)) throw new Error('Таңдалған әліпбидің әріптерін енгізіңіз.');
    if (!values.length) return {output: '', rows};
  }

  const stream = await aesStream(key, values.length);
  const output = values.map((value, i) => {
    const byte = stream[i];
    const middle = decrypt ? modPow(value, 173) : value ^ byte;
    const next = decrypt ? middle ^ byte : modPow(middle, 5);
    if (decrypt && (middle > 255 || next >= letters.length)) {
      throw new Error('Жарамсыз шифрмәтін. Кілт пен әліпбиді тексеріңіз.');
    }
    const calculation = decrypt
      ? value + '¹⁷³ mod 323 = ' + middle + '; ' + middle + ' ⊕ ' + byte + ' = ' + next
      : value + ' ⊕ ' + byte + ' = ' + middle + '; ' + middle + '⁵ mod 323 = ' + next;
    const result = decrypt ? letters[next] : next;
    rows.push({value: next, cells: [decrypt ? value : letters[value] + ' · ' + value, byte, calculation, result]});
    return result;
  }).join(decrypt ? '' : ' ');
  return {output, rows};
}

function chart(prefix, rows) {
  const values = rows.slice(0, 8).map(row => row.value);
  const container = byId(prefix + 'Chart');
  if (!values.length) {
    container.textContent = '';
    return;
  }
  const max = Math.max(1, ...values);
  const color = prefix === 'aes' ? 'var(--c1)' : 'var(--c2)';
  const bars = values.map((value, index) => {
    const x = 28 + index * 47;
    const height = Math.max(1, value * 66 / max);
    return '<g><rect x="' + (x - 12) + '" y="' + (91 - height) +
      '" width="24" height="' + height + '" rx="3"/><text x="' + x + '" y="' +
      (86 - height) + '">' + value + '</text><text x="' + x + '" y="106">' + (index + 1) + '</text></g>';
  }).join('');
  container.innerHTML = '<svg viewBox="0 0 384 112" role="img" aria-label="Алғашқы нәтижелер" fill="' +
    color + '" text-anchor="middle" font-size="11"><path d="M5 91H379" stroke="var(--line)"/>' + bars + '</svg>';
}

function setupCipher(prefix) {
  const input = byId('i_' + prefix);
  const key = byId('k_' + prefix);
  const result = byId('o_' + prefix);
  const status = byId(prefix + 'Status');
  const enc = byId(prefix + 'Enc');
  const dec = byId(prefix + 'Dec');
  let decrypt = false;
  let rows = [];
  let revision = 0;
  let page = 0;
  let model = 0;

  function renderRows() {
    const start = page * 4;
    const body = byId(prefix + 'Rows');
    body.replaceChildren();
    rows.slice(start, start + 4).forEach((row, index) => {
      const tr = body.insertRow();
      [start + index + 1, ...row.cells].forEach(value => { tr.insertCell().textContent = value; });
    });
    byId(prefix + 'CalcPage').textContent = rows.length
      ? (start + 1) + '–' + Math.min(start + 4, rows.length) + ' / ' + rows.length : '0 / 0';
    byId(prefix + 'CalcPrev').disabled = page === 0;
    byId(prefix + 'CalcNext').disabled = start + 4 >= rows.length;
  }

  async function run() {
    const current = ++revision;
    status.textContent = '';
    result.textContent = '';
    rows = [];
    page = 0;
    renderRows();
    chart(prefix, rows);
    if (!input.value.trim()) return;
    try {
      if (!/^\d+$/.test(key.value)) throw new Error('Кілтке тек 0–9 цифрларын енгізіңіз.');
      const data = await calculate(prefix, input.value, key.value, decrypt, alphabet);
      if (current !== revision) return;
      result.textContent = data.output;
      rows = data.rows;
      renderRows();
      chart(prefix, rows);
    } catch (error) {
      if (current === revision) status.textContent = error.message;
    }
  }

  function mode(next) {
    decrypt = next;
    [[enc, !next], [dec, next]].forEach(([button, active]) => {
      button.classList.toggle('on', active);
      button.setAttribute('aria-pressed', active);
    });
    byId(prefix + 'InputLabel').textContent = next ? 'Шифрмәтін' : 'Ашық мәтін';
    byId(prefix + 'OutputLabel').textContent = next ? 'Ашық мәтін' : 'Шифрмәтін';
    byId(prefix + 'Formula').textContent = prefix === 'aes'
      ? (next ? 'Xᵢ = Rᵢ¹⁷³ mod 323; Mᵢ = Xᵢ ⊕ Sᵢ' : 'S = AES-CTR(K, 0); Xᵢ = Mᵢ ⊕ Sᵢ; Rᵢ = Xᵢ⁵ mod 323')
      : (next ? 'Mᵢ = (Cᵢ − Kᵢ + N) mod N' : 'Cᵢ = (Mᵢ + Kᵢ) mod N');
    run();
  }

  function renderModel() {
    const [label, formula] = models[prefix][model];
    const target = byId(prefix + 'Math');
    target.querySelector('.model-label').textContent = 'Формула · ' + label;
    target.querySelector('.fm').textContent = formula;
    byId(prefix + 'ModelPage').textContent = (model + 1) + ' / ' + models[prefix].length;
    byId(prefix + 'ModelPrev').disabled = model === 0;
    byId(prefix + 'ModelNext').disabled = model === models[prefix].length - 1;
  }

  enc.onclick = () => mode(false);
  dec.onclick = () => mode(true);
  input.oninput = key.oninput = run;
  byId(prefix + 'Clear').onclick = () => { input.value = ''; run(); input.focus(); };
  byId(prefix + 'Copy').onclick = async () => {
    if (!result.textContent) return;
    try {
      await navigator.clipboard.writeText(result.textContent);
      status.textContent = 'Көшірілді.';
    } catch {
      status.textContent = 'Нәтижені белгілеп, қолмен көшіріңіз.';
    }
  };
  byId(prefix + 'CalcPrev').onclick = () => { page--; renderRows(); };
  byId(prefix + 'CalcNext').onclick = () => { page++; renderRows(); };
  byId(prefix + 'ModelPrev').onclick = () => { model--; renderModel(); };
  byId(prefix + 'ModelNext').onclick = () => { model++; renderModel(); };
  renderModel();
  return run;
}

byId('i_aes').value = byId('i_vig').value = 'ХАБАРЛАМА';
const refresh = ['aes', 'vig'].map(setupCipher);
function selectAlphabet(card) {
  alphabet = Array.from(card.querySelectorAll('.abl span'), span => span.textContent).join('');
  alphabetCards.forEach(item => {
    item.classList.toggle('on', item === card);
    item.setAttribute('aria-pressed', item === card);
  });
  refresh.forEach(run => run());
}
alphabetCards.forEach(card => {
  card.onclick = () => selectAlphabet(card);
  card.onkeydown = event => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      card.click();
    }
  };
});
selectAlphabet(alphabetCards.find(card => card.dataset.al === 'kk'));

function showPanel(id) {
  ['installHelp', 'aiPanel'].forEach(panel => { byId(panel).hidden = panel !== id; });
  byId('hb').setAttribute('aria-expanded', id === 'aiPanel');
}
window.addEventListener('beforeinstallprompt', event => {
  event.preventDefault();
  installPrompt = event;
});
byId('installBtn').onclick = async () => {
  if (installPrompt) {
    const prompt = installPrompt;
    installPrompt = null;
    await prompt.prompt();
    return;
  }
  byId('installHelpContent').textContent =
    'Android Chrome: ⋮ мәзірінен «Қолданбаны орнату» немесе «Басты экранға қосу» тармағын таңдаңыз. iPhone Safari: «Бөлісу» → «Басты экранға қосу».';
  showPanel('installHelp');
};
byId('closeInstallHelp').onclick = () => showPanel('');
byId('hb').onclick = () => showPanel(byId('aiPanel').hidden ? 'aiPanel' : '');
byId('aiX').onclick = () => showPanel('');

function answer(question) {
  if (!question.trim()) return;
  const query = question.toLowerCase();
  let response = 'AES, RSA, Вижинер немесе нәтиже туралы сұраңыз.';
  if (query.includes('нәтиже')) {
    response = 'AES + RSA: ' + (byId('o_aes').textContent || '—') + '\nВижинер: ' +
      (byId('o_vig').textContent || '—') + '\nӘр таңбаның түрленуін қадамдық есеп кестесінен қараңыз.';
  } else if (query.includes('aes') && query.includes('rsa')) {
    response = 'Оқу моделінде әріп индексі алдымен AES ағынының байтымен XOR арқылы түрленеді. Содан кейін RSA модулі бойынша есептеледі.';
  } else if (query.includes('rsa')) {
    response = 'RSA дәрежелеу мен модульге негізделеді. Оқу мысалында n = 323, e = 5, d = 173.';
  } else if (query.includes('aes')) {
    response = 'Бұл мысалда сандық кілт SHA-256 арқылы өңделеді. Алғашқы 16 байт AES-CTR кілті ретінде қолданылады.';
  } else if (query.includes('вижинер')) {
    response = 'Вижинер әр әріпті сандық кілттің кезекті цифрына жылжытады. Кері шифрлау кезінде осы ығысу шегеріледі.';
  }
  const log = byId('aiLog');
  [['me', question], ['bot', response]].forEach(([kind, message]) => {
    const node = document.createElement('div');
    node.className = 'msg ' + kind;
    node.textContent = message;
    log.append(node);
  });
  log.scrollTop = log.scrollHeight;
}
byId('aiSend').onclick = () => {
  answer(byId('aiIn').value);
  byId('aiIn').value = '';
};
byId('aiIn').onkeydown = event => { if (event.key === 'Enter') byId('aiSend').click(); };
document.querySelectorAll('#aiChips button').forEach(button => {
  button.onclick = () => answer(button.textContent);
});
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('./sw.js').catch(error => console.warn('Offline cache:', error));
}
