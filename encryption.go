// ENCRYPTION

func (b *backend) encrypt(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("Invoked: Encryption")

	message := data.Get("message").(string)
	policy_str := data.Get("policy").(string)

	if len(message) == 0 {
		return logical.ErrorResponse("Empty message for encryption"), nil
	}

	ecElement := b.getABEElement()

	s := ecElement.Pairing().NewZr().Rand()
	w := ecElement.Pairing().NewZr()

	randomnessGenerator := ecElement.Pairing().NewGT().Rand() // A random element `randomnessGenerator` in GT is created - It will be used to correlate a key with the EC
	randomKey := sha256.Sum256([]byte(randomnessGenerator.String()))

	cipher, err := aes.NewCipher(randomKey[:])

	if err != nil {
		return nil, errwrap.Wrapf("error in encryption: {{err}}", err)
	}

	iv := make([]byte, cipher.BlockSize())
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, errwrap.Wrapf("error in encryption: {{err}}", err)
	}

	secretMessageAsBytes := []byte(message) // The message (string) as a byte's slice
	paddingLength := cipher.BlockSize() - (len(secretMessageAsBytes) % cipher.BlockSize())
	secretMsgPadded := make([]byte, len(secretMessageAsBytes)+paddingLength)
	copy(secretMsgPadded, secretMessageAsBytes)
	for i := len(secretMessageAsBytes); i < len(secretMsgPadded); i++ {
		secretMsgPadded[i] = byte(paddingLength)
	}

	encrypter := cbc.NewCBCEncrypter(cipher, iv)
	symmetricEncryptedMessage := make([]byte, len(secretMsgPadded))
	encrypter.CryptBlocks(symmetricEncryptedMessage, secretMsgPadded)

	egg_s := ecElement.Pairing().NewGT()
	egg_s.Pair(ecElement, ecElement).ThenPowZn(s)

	messageMap := ecElement.Pairing().NewGT().Set(egg_s).ThenMul(randomnessGenerator).Bytes()

	policy := createPolicy(policy_str)
	sshares, wshares := make(map[string]*pbc.Element), make(map[string]*pbc.Element)
	policy.calculateSharesList(ecElement, s, sshares)
	policy.calculateSharesList(ecElement, w, wshares)

	C1El, C2El, C3El := make(map[string][]byte), make(map[string][]byte), make(map[string][]byte)

	attributesList, err := b.allAttributesPutTogether(ctx, req)

	if err != nil {
		return nil, errwrap.Wrapf("read failed: {{err}}", err)
	}

	unavailableAttrs, CheckedAttrs := b.checkAttributesAvailability(sshares, attributesList)

	if unavailableAttrs {
		return &logical.Response{
			Data: map[string]interface{}{
				"attributes_availability": CheckedAttrs,
			},
		}, nil
	}

	for attr := range sshares {
		attribute := strings.ToUpper(attr)

		eggAlphaI := ecElement.Pairing().NewGT().SetBytes(attributesList[attribute].Alphai)
		gYI := ecElement.Pairing().NewG1().SetBytes(attributesList[attribute].Yi)

		w_share := fmt.Sprint(wshares[attr])
		s_share := fmt.Sprint(sshares[attr])
		s_shareBig := new(big.Int)
		w_shareBig := new(big.Int)
		s_shareBig, err_sshare := s_shareBig.SetString(s_share, 10)
		w_shareBig, err_wshare := w_shareBig.SetString(w_share, 10)
		_, _ = err_sshare, err_wshare

		r_x := ecElement.Pairing().NewZr().Rand()

		fieldC1Base := ecElement.Pairing().NewGT()

		fieldC1V1 := ecElement.Pairing().NewGT()
		fieldC1V1v1 := ecElement.Pairing().NewGT().Pair(ecElement, ecElement)
		fieldC1V1.Set(fieldC1V1v1).ThenPowBig(s_shareBig)

		fieldC1V2 := ecElement.Pairing().NewGT()
		fieldC1V2.Set(eggAlphaI)
		fieldC1V2.ThenPowZn(r_x)

		fieldC1Base.Mul(fieldC1V1, fieldC1V2)

		C1El[attr] = fieldC1Base.Bytes()

		fieldC2Base := ecElement.Pairing().NewG1()
		fieldC2Base.Set(ecElement).ThenPowZn(r_x)

		C2El[attr] = fieldC2Base.Bytes()

		fieldC3Base := ecElement.Pairing().NewG1()

		fieldC3V1 := ecElement.Pairing().NewG1()
		fieldC3V1.Set(gYI).ThenPowZn(r_x)

		fieldC3V2 := ecElement.Pairing().NewG1()
		fieldC3V2.Set(ecElement).ThenPowBig(w_shareBig)

		fieldC3Base.Set(fieldC3V1).ThenMul(fieldC3V2)

		C3El[attr] = fieldC3Base.Bytes()
	}

	generatedData := cryptogram{
		C0:               messageMap,
		C1:               C1El,
		C2:               C2El,
		C3:               C3El,
		EncryptedMessage: symmetricEncryptedMessage,
		CipherIV:         iv,
		PolicyStr:        policy_str,
	}

	exported, err := json.Marshal(generatedData)
	if err != nil {
		return nil, err
	}

	b64Encoded := b64.StdEncoding.EncodeToString([]byte(exported))

	return &logical.Response{
		Data: map[string]interface{}{
			"b64_enc_data": b64Encoded,
		},
	}, nil
}
