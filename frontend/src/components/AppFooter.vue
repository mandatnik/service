<script setup>
import { ref } from 'vue'
const authorsDialog = ref(null)
function closeOnBackdrop(event) {
  if (event.target !== authorsDialog.value) return
  const bounds = authorsDialog.value.getBoundingClientRect()
  if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) authorsDialog.value.close()
}
</script>

<template>
  <footer class="app-footer">
    <span>Мандатник · Панель администратора</span>
    <span class="footer-copyright">© <button type="button" class="footer-author" aria-haspopup="dialog" @click="authorsDialog.showModal()">Малыгин А. Е.</button> и <button type="button" class="footer-author" aria-haspopup="dialog" @click="authorsDialog.showModal()">Цукров М. Е.</button></span>
  </footer>
  <dialog ref="authorsDialog" class="authors-dialog" aria-labelledby="authors-heading" @click="closeOnBackdrop">
    <header class="authors-dialog-heading">
      <h2 id="authors-heading">Авторы</h2>
      <button type="button" class="dialog-close" aria-label="Закрыть окно авторов" autofocus @click="authorsDialog.close()"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18" /></svg></button>
    </header>
    <section class="author-details" aria-labelledby="author-malygin">
      <h3 id="author-malygin">Малыгин Александр Евгеньевич</h3>
      <p class="author-tax-id">ИНН 861006744079</p>
      <dl class="author-contacts">
        <dt>Почта</dt><dd><a href="mailto:mimbol@yandex.ru">mimbol@yandex.ru</a></dd>
        <dt>Telegram</dt><dd><a href="https://t.me/malygin_ae" target="_blank" rel="noopener noreferrer">@malygin_ae<span class="sr-only"> (откроется в новой вкладке)</span></a></dd>
      </dl>
    </section>
    <section class="author-details" aria-labelledby="author-tsukrov">
      <h3 id="author-tsukrov">Цукров Михаил Евгеньевич</h3>
      <p class="author-tax-id">ИНН 662706878980</p>
      <dl class="author-contacts">
        <dt>Почта</dt><dd><a href="mailto:tsukrov.me@yandex.ru">tsukrov.me@yandex.ru</a></dd>
      </dl>
    </section>
  </dialog>
</template>
