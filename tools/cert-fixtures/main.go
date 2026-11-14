// Создает изолированный набор открытых тестовых сертификатов и проверяет подписи.
package main

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gost-sig/backend"
	"gost-sig/backend/soft"
	"gost-sig/gostca"
	"gost-sig/store/filestore"
	"gost-sig/x509gost"
)

type scenario struct {
	Slug, Kind, Name, State, Profile, Note string
	Bits                                   int
	NoINN, NoEmail                         bool
}

type entry struct {
	ID            int       `json:"id"`
	File          string    `json:"file"`
	PEM           string    `json:"pem"`
	Kind          string    `json:"owner_type"`
	Subject       string    `json:"subject"`
	Serial        string    `json:"serial_hex"`
	SHA256        string    `json:"sha256_der"`
	PublicKeyBits int       `json:"public_key_bits"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	State         string    `json:"expected_time_status_at_reference"`
	Profile       string    `json:"profile"`
	Note          string    `json:"scenario"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func write(path string, data []byte) {
	must(os.MkdirAll(filepath.Dir(path), 0755))
	must(os.WriteFile(path, data, 0644))
}
func fingerprint(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func algorithm(bits int) backend.Algorithm {
	p := x509gost.OIDParamSet256A
	if bits == 512 {
		p = x509gost.OIDParamSet512A
	}
	return backend.Algorithm{Bits: bits, ParamSet: p}
}

func subject(i int, sc scenario) x509gost.Name {
	attrs := []x509gost.NameAttribute{
		{Type: x509gost.OIDCountry, Value: "RU"},
		{Type: x509gost.OIDStateOrProvince, Value: "Свердловская область"},
		{Type: x509gost.OIDLocality, Value: "Екатеринбург"},
		{Type: x509gost.OIDCommonName, Value: sc.Name},
	}
	add := func(oid asn1.ObjectIdentifier, val string) {
		attrs = append(attrs, x509gost.NameAttribute{Type: oid, Value: val})
	}
	if !sc.NoEmail {
		add(x509gost.OIDEmailAddress, fmt.Sprintf("fixture-%02d@example.test", i))
	}
	if !sc.NoINN {
		add(x509gost.OIDINN, fmt.Sprintf("00000000%04d", i))
	}
	switch sc.Kind {
	case "individual":
		add(x509gost.OIDSNILS, fmt.Sprintf("0000000%04d", i))
	case "sole_proprietor":
		add(x509gost.OIDOrganization, "ИП "+sc.Name)
		add(x509gost.OIDOGRNIP, fmt.Sprintf("00000000000%04d", i))
	case "legal_entity":
		add(x509gost.OIDOrganization, fmt.Sprintf("ООО «Тестовая организация %02d»", i))
		add(x509gost.OIDOrganizationalUnit, "Тестовый отдел электронного документооборота")
		add(x509gost.OIDINNLE, fmt.Sprintf("000000%04d", i))
		add(x509gost.OIDKPP, "000000000")
		add(x509gost.OIDOGRN, fmt.Sprintf("000000000%04d", i))
	}
	n, err := x509gost.NewName(attrs...)
	must(err)
	return n
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: cert-fixtures /absolute/project/path")
	}
	project := os.Args[1]
	out := filepath.Join(project, "test-data", "certificates-2026-11-14")
	private := filepath.Join(project, ".secrets", "test-ca-2026-11-14")
	for _, dir := range []string{out, private} {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			panic("refusing to overwrite: " + dir)
		}
	}
	must(os.MkdirAll(private, 0700))
	ref, err := time.Parse(time.RFC3339, "2026-11-14T12:00:00+05:00")
	must(err)
	engine := soft.New()
	st, err := filestore.New(filepath.Join(private, "ca-state"))
	must(err)
	caSubject, err := x509gost.NewName(
		x509gost.NameAttribute{Type: x509gost.OIDCountry, Value: "RU"},
		x509gost.NameAttribute{Type: x509gost.OIDOrganization, Value: "Telehack 2026 — тестовая инфраструктура"},
		x509gost.NameAttribute{Type: x509gost.OIDCommonName, Value: "Telehack 2026 TEST ONLY Root CA"},
	)
	must(err)
	ca, err := gostca.Init(gostca.InitOptions{Backend: engine, Store: st, KeyRef: filepath.Join(private, "root.key.pem"), Algorithm: algorithm(256), Subject: caSubject, Profile: "ca", NotBefore: ref.AddDate(-10, 0, 0), Validity: 30 * 365 * 24 * time.Hour})
	must(err)
	must(engine.Verify(ca.Cert.PublicKey, backend.Digest256, ca.Cert.RawTBS, ca.Cert.Signature))
	if !ca.Cert.IsCA {
		panic("root must be CA")
	}
	write(filepath.Join(out, "root", "root-ca.cer"), ca.CertDER)
	write(filepath.Join(out, "root", "root-ca.pem"), x509gost.EncodePEM(x509gost.PEMCertificate, ca.CertDER))
	scenarios := []scenario{
		{Slug: "individual-valid", Kind: "individual", Name: "Тестов Иван Иванович", State: "valid", Profile: "russian-ecp", Bits: 256, Note: "Физлицо: обычный действующий сертификат"},
		{Slug: "individual-expired", Kind: "individual", Name: "Тестова Анна Петровна", State: "expired", Profile: "russian-ecp", Bits: 256, Note: "Физлицо: срок закончился 30 дней назад"},
		{Slug: "individual-future", Kind: "individual", Name: "Образцов Петр Сергеевич", State: "not_yet_valid", Profile: "russian-ecp", Bits: 256, Note: "Физлицо: начнет действовать через 30 дней"},
		{Slug: "individual-expires-soon", Kind: "individual", Name: "Примерова Елена Андреевна", State: "valid", Profile: "russian-ecp", Bits: 256, Note: "Физлицо: истекает через 7 дней"},
		{Slug: "individual-no-inn", Kind: "individual", Name: "Проверкин Алексей Игоревич", State: "valid", Profile: "russian-ecp", Bits: 256, NoINN: true, Note: "Физлицо: отсутствует ИНН"},
		{Slug: "individual-email-profile", Kind: "individual", Name: "Тестова Мария Олеговна", State: "valid", Profile: "email", Bits: 256, Note: "Физлицо: назначение защиты электронной почты"},
		{Slug: "individual-expired-no-email", Kind: "individual", Name: "Пробный Дмитрий Павлович", State: "expired", Profile: "russian-ecp", Bits: 256, NoEmail: true, Note: "Физлицо: просроченный, без email"},
		{Slug: "individual-gost512", Kind: "individual", Name: "Образцова Ольга Николаевна", State: "valid", Profile: "russian-ecp", Bits: 512, Note: "Физлицо: ГОСТ-ключ 512 бит"},
		{Slug: "ip-valid", Kind: "sole_proprietor", Name: "Тестов Сергей Викторович", State: "valid", Profile: "russian-ecp", Bits: 256, Note: "ИП: ИНН и ОГРНИП"},
		{Slug: "ip-expired", Kind: "sole_proprietor", Name: "Проверкина Ирина Алексеевна", State: "expired", Profile: "russian-ecp", Bits: 256, Note: "ИП: просроченный"},
		{Slug: "ip-future", Kind: "sole_proprietor", Name: "Примеров Андрей Михайлович", State: "not_yet_valid", Profile: "russian-ecp", Bits: 256, Note: "ИП: еще не вступил в силу"},
		{Slug: "ip-expires-soon", Kind: "sole_proprietor", Name: "Образцова Наталья Юрьевна", State: "valid", Profile: "russian-ecp", Bits: 256, Note: "ИП: истекает через 7 дней"},
		{Slug: "ip-gost512", Kind: "sole_proprietor", Name: "Пробный Максим Романович", State: "valid", Profile: "russian-ecp", Bits: 512, Note: "ИП: ГОСТ-ключ 512 бит"},
		{Slug: "ip-client-auth", Kind: "sole_proprietor", Name: "Тестова Екатерина Ильинична", State: "valid", Profile: "tls-client", Bits: 256, Note: "ИП: клиентская аутентификация"},
		{Slug: "company-director-valid", Kind: "legal_entity", Name: "Тестов Павел Андреевич", State: "valid", Profile: "russian-ecp", Bits: 256, Note: "Юрлицо: представитель организации, ИНН ЮЛ, КПП, ОГРН"},
		{Slug: "company-expired", Kind: "legal_entity", Name: "Примерова Светлана Борисовна", State: "expired", Profile: "russian-ecp", Bits: 256, Note: "Юрлицо: просроченный"},
		{Slug: "company-gost512", Kind: "legal_entity", Name: "Образцов Николай Петрович", State: "valid", Profile: "russian-ecp", Bits: 512, Note: "Юрлицо: ГОСТ-ключ 512 бит"},
		{Slug: "company-expires-soon", Kind: "legal_entity", Name: "Проверкин Виктор Семенович", State: "valid", Profile: "russian-ecp", Bits: 256, Note: "Юрлицо: истекает через 7 дней"},
		{Slug: "company-long-name-expired", Kind: "legal_entity", Name: "Тестовая-Образцова Александра Константиновна", State: "expired", Profile: "russian-ecp", Bits: 256, Note: "Юрлицо: длинное кириллическое имя и просроченный срок"},
		{Slug: "company-expired-no-email", Kind: "legal_entity", Name: "Пробный Михаил Федорович", State: "expired", Profile: "russian-ecp", Bits: 256, NoEmail: true, Note: "Юрлицо: просроченный сертификат без email"},
	}
	entries := []entry{}
	seenDER, seenSerial, seenKey := map[string]bool{}, map[string]bool{}, map[string]bool{}
	counts := map[string]int{}
	for idx, sc := range scenarios {
		i := idx + 1
		name := fmt.Sprintf("%02d-%s", i, sc.Slug)
		nb, na := ref.AddDate(0, 0, -30), ref.AddDate(1, 0, 0)
		switch sc.State {
		case "expired":
			nb, na = ref.AddDate(-2, 0, 0), ref.AddDate(0, 0, -30)
		case "not_yet_valid":
			nb, na = ref.AddDate(0, 0, 30), ref.AddDate(1, 0, 30)
		}
		if strings.Contains(sc.Slug, "expires-soon") {
			na = ref.AddDate(0, 0, 7)
		}
		der, key, _, err := ca.IssueKey(algorithm(sc.Bits), filepath.Join(private, "leaf-keys", name+".key.pem"), subject(i, sc), gostca.IssueOptions{Profile: sc.Profile, NotBefore: nb, Validity: na.Sub(nb)})
		must(err)
		c, err := x509gost.ParseCertificate(der)
		must(err)
		must(engine.Verify(ca.Cert.PublicKey, backend.Digest256, c.RawTBS, c.Signature))
		pub, err := key.Public()
		must(err)
		fp, serial, keyfp := fingerprint(der), c.SerialNumber.Text(16), fingerprint(pub.PublicKey.Bytes)
		if seenDER[fp] || seenSerial[serial] || seenKey[keyfp] || c.IsCA || c.Issuer.String() != ca.Cert.Subject.String() {
			panic("invalid/duplicate certificate")
		}
		seenDER[fp], seenSerial[serial], seenKey[keyfp] = true, true, true
		actual := "valid"
		if ref.Before(c.NotBefore) {
			actual = "not_yet_valid"
		} else if ref.After(c.NotAfter) {
			actual = "expired"
		}
		if actual != sc.State || !c.NotBefore.Equal(nb) || !c.NotAfter.Equal(na) {
			panic("validity mismatch")
		}
		cer, pemPath := "certificates/"+name+".cer", "pem/"+name+".pem"
		write(filepath.Join(out, cer), der)
		write(filepath.Join(out, pemPath), x509gost.EncodePEM(x509gost.PEMCertificate, der))
		entries = append(entries, entry{i, cer, pemPath, sc.Kind, c.Subject.String(), serial, fp, sc.Bits, c.NotBefore, c.NotAfter, sc.State, sc.Profile, sc.Note})
		counts[actual]++
	}
	manifest := map[string]any{"schema_version": 1, "test_only": true, "reference_time": ref, "root": "root/root-ca.cer", "root_sha256_der": fingerprint(ca.CertDER), "root_not_before": ca.Cert.NotBefore, "root_not_after": ca.Cert.NotAfter, "counts": counts, "signature_verification": "all 20 issuer signatures and root self-signature verified using soft backend", "certificates": entries}
	data, err := json.MarshalIndent(manifest, "", "  ")
	must(err)
	write(filepath.Join(out, "manifest.json"), append(data, '\n'))
	var readme strings.Builder
	readme.WriteString("# Тестовые сертификаты Telehack 2026\n\nСамоподписанный корневой ГОСТ УЦ и 20 разных конечных сертификатов. Все имена и реквизиты синтетические; ИНН/ОГРН/СНИЛС — намеренные тестовые заглушки, без проверки контрольных цифр. Это не квалифицированные сертификаты и не доказательство полномочий владельца.\n\nСтатусы ниже рассчитаны на **2026-11-14 12:00:00 +05:00**. По мере течения времени они изменяются. `valid` означает только попадание в интервал дат, не доверие ОС и не проверку отзыва.\n\n- `root/` — корневой сертификат DER .cer и PEM.\n- `certificates/` — ровно 20 DER .cer для сканирования файлов.\n- `pem/` — те же 20 сертификатов в PEM, не дополнительные сертификаты.\n- `manifest.json` — ожидаемые поля, даты, отпечатки и сценарии.\n\n12 действующих, 6 просроченных, 2 еще не вступивших в силу. Из действующих 3 истекают через 7 дней. Владельцы: 8 физлиц, 6 ИП, 6 представителей юрлиц. У 3 владельцев ключи ГОСТ-2012 512 бит, у остальных 256; подпись всех конечных сертификатов — корневым ГОСТ-2012 256-битным ключом. Ни один конечный сертификат не является УЦ.\n\nЛицензия КриптоПро не встраивалась; выпуск сертификатов не создает лицензию CSP. Сертификаты не отозваны; CRL/OCSP не выпускались. Ключи созданы программным бэкендом и не импортировались в КриптоПро или системные хранилища.\n\nДля проверки папок укажите в админке `certificates/`. Для повторного обнаружения одного сертификата скопируйте один и тот же .cer в разные папки/машины: SHA-256 DER должен остаться одинаковым. Для проверки личных хранилищ можно импортировать публичные .cer в CurrentUser\\My тестового пользователя; это не добавит закрытый ключ и не даст возможности подписывать. Импорт доверенного корня является отдельным действием и автоматически не выполнялся.\n\nЗакрытые тестовые ключи и состояние УЦ хранятся отдельно в `.secrets/test-ca-2026-11-14/` (исключено из Git), не входят в публичный ZIP. Они позволяют повторно использовать этот тестовый УЦ; никакие существующие ключи не затронуты. Для повторной генерации в новой папке адаптируйте пути в `tools/cert-fixtures/main.go`; генератор отказывается перезаписывать существующий набор.\n\n## Сценарии\n\n| № | Файл | Статус на контрольную дату | Сценарий |\n| --- | --- | --- | --- |\n")
	for _, e := range entries {
		fmt.Fprintf(&readme, "| %d | %s | %s | %s |\n", e.ID, filepath.Base(e.File), e.State, e.Note)
	}
	write(filepath.Join(out, "README.md"), []byte(readme.String()))
	fmt.Printf("Created root + %d leaf certificates. Status counts: %v. All signatures verified.\nOutput: %s\n", len(entries), counts, out)
}
