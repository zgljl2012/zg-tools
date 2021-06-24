<template>
  <v-row justify="center" align="center">
    <v-col cols="12" sm="8" md="6">
      <div class="text-center">
        
      </div>
      <v-card>
        <v-card-title class="headline">
          ECC椭圆曲线算法在线密码生成
        </v-card-title>
        <v-card-text>
          <v-container>
            <v-row>
              <v-col cols="12">
                <v-btn class="primary">生成公私钥</v-btn>
              </v-col>
            </v-row>
            <v-row>
              <v-col cols="12">ECC 私钥</v-col>
            </v-row>
            <v-row>
              <v-col cols="12">
                <v-textarea
                  solo
                  disabled
                  name="input-7-4"
                  label="私钥"
                ></v-textarea>
              </v-col>
            </v-row>
            <v-row>
              <v-col cols="12">ECC 公钥</v-col>
            </v-row>
            <v-row>
              <v-col cols="12">
                <v-textarea
                  solo
                  disabled
                  name="input-7-4"
                  label="公钥"
                ></v-textarea>
              </v-col>
            </v-row>
            <v-row>
              <v-col cols="12"></v-col>
            </v-row>
          </v-container>
        </v-card-text>
      </v-card>
      <v-card class="mt-8">
        <v-card-title class="headline">
          ECC椭圆曲线算法在线加密验证
        </v-card-title>
        <v-card-text>
          <v-container>
            <v-row>
              <v-col cols="12">ECC 私钥</v-col>
            </v-row>
            <v-row>
              <v-col cols="12">
                <v-textarea
                  solo
                  name="input-7-4"
                  label="请输入 ECC 私钥"
                ></v-textarea>
              </v-col>
            </v-row>
            <v-row>
              <v-col cols="12">待加密明文</v-col>
            </v-row>
            <v-row>
              <v-col cols="12">
                <v-textarea
                  solo
                  name="input-7-4"
                  label="请输入待加密明文"
                ></v-textarea>
              </v-col>
            </v-row>
            <v-row>
              <v-col cols="3">
                <v-btn color="primary" nuxt>加密</v-btn>
              </v-col>
            </v-row>
            <v-row>
              <v-col cols="12">密文</v-col>
            </v-row>
            <v-row>
              <v-col cols="12">
                <v-textarea
                  solo
                  disabled
                  name="input-7-4"
                  label="密文"
                ></v-textarea>
              </v-col>
            </v-row>
          </v-container>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <!-- <v-btn
            color="primary"
            nuxt
            to="/inspire"
          >
            Continue
          </v-btn> -->
        </v-card-actions>
      </v-card>
    </v-col>
  </v-row>
</template>

<script>
import Logo from '~/components/Logo.vue'
import VuetifyLogo from '~/components/VuetifyLogo.vue'

export default {
  components: {
    Logo,
    VuetifyLogo
  }
}
</script>
