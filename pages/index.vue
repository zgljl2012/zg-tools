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
                <v-btn class="primary" @click="generatePair()">生成公私钥</v-btn>
              </v-col>
            </v-row>
            <v-row>
              <v-col cols="12">ECC 私钥</v-col>
            </v-row>
            <v-row>
              <v-col cols="12">
                <v-textarea
                  v-model="generated_pri"
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
                  v-model="generated_pub"
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
import * as crypto from 'crypto-js'
import * as elliptic from 'elliptic'
import * as asn from 'asn1.js'

export default {
  components: {
    Logo,
    VuetifyLogo
  },
  data() {
    return {
      generated_pub: '',
      generated_pri: '',
    }
  },
  methods: {
    generatePair() {
      const ec = new elliptic.ec('secp256k1')
      const keyPair = ec.genKeyPair();
      var CURVE = [1, 3, 132, 0, 10] // :secp256k1

      var ECPublicKey = asn.define("PublicKey", function() {
        this.seq().obj(
          this.key("algorithm").seq().obj(
            this.key("id").objid(),
            this.key("curve").objid()
          ),
          this.key("pub").bitstr()
        );
      });

      var ECPrivateKey = asn.define("ECPrivateKey", function() {
        this.seq().obj(
          this.key('version').int(),
          this.key('privateKey').octstr(),
          this.key('parameters').explicit(0).objid().optional(),
          this.key('publicKey').explicit(1).bitstr().optional()
        );
      });

      this.generated_pub = ECPublicKey.encode({
        algorithm: {
          // :id-ecPublicKey
          id: [1, 2, 840, 10045, 2, 1],
          curve: CURVE,
        },
        pub: {
          unused: 0,
          data: new Buffer(keyPair.getPublic("array")),
        },
      }, "pem", {label: "PUBLIC KEY"});

      this.generated_pri = ECPrivateKey.encode({
        version: 1,
        parameters: CURVE,
        publicKey: {data: new Buffer(keyPair.getPublic("array"))},
        privateKey: new Buffer(keyPair.getPrivate().toArray())
      }, "pem", {label: "EC PRIVATE KEY"});
    }
  }
}
</script>
