target_string = "Fcn_yDlvaGpj_Logi}eias{iaeAm_s"
password = [''] * 30

for i in range(30):
    password[(i * 7) % 30] = target_string[i]

password = ''.join(password)
print(password)
