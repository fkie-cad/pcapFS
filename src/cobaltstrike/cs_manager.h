#ifndef PCAPFS_CS_MANAGER_H
#define PCAPFS_CS_MANAGER_H

#include <set>
#include "../commontypes.h"

namespace pcapfs {

    typedef struct CobaltStrikeConnection {
        std::string serverIp;
        std::string serverPort;
        std::string clientIp;
        Bytes aesKey;

    } CobaltStrikeConnection;

    typedef std::shared_ptr<CobaltStrikeConnection> CobaltStrikeConnectionPtr;

    class CobaltStrikeManager {
    public:
        static CobaltStrikeManager& getInstance() {
            static CobaltStrikeManager instance;
            return instance;
        }

        CobaltStrikeManager(CobaltStrikeManager const&) = delete;
        void operator=(CobaltStrikeManager const&) = delete;

        void handleHttpGet(const std::string &cookie, const std::string &dstIp, const std::string &dstPort, const std::string &srcIp);
        CobaltStrikeConnectionPtr getConnectionData(const std::string &serverIp, const std::string &serverPort, const std::string &clientIp);
        bool isKnownConnection(const std::string &serverIp, const std::string &serverPort, const std::string &clientIp);

    private:
        CobaltStrikeManager() {}

        bool matchMagicBytes(const Bytes& input);
        void addConnectionData(const Bytes &rawKey, const std::string &dstIp, const std::string &dstPort, const std::string &srcIp);

        std::vector<CobaltStrikeConnectionPtr> connections;

        const std::set<std::string> privKeyCandidates = {
                            "-----BEGIN RSA PRIVATE KEY-----\n" \
                            "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKc4zedfH7scGGRs\n" \
                            "N34DAWsWKxK6cr333Da0zS5Om64SIFqVwmFwv5CBBa1/pLvM+nmGMiYb7Zhw+XXy\n" \
                            "B5Th/kmVI9cfCKVsrgMVv949bIoWOGsDt6ZVGqEzbVAyWjUA2yfXitj9E7anO5+3\n" \
                            "w/tNegiOMj8HYYZW7Ng1lfpfgjYTAgMBAAECgYBZ63DFTuB4NBZlwc9hQmp71BLb\n" \
                            "YkkbH/JZtIV0ti5+vx6It2ksDn3kTYzpC+9gUUwLFv9WgMQVqgJqyvgKti+PMGmM\n" \
                            "cTJTDd1GpEt3dzhwNzEuScWdxaAOIJZ0NfdMrGcDogHsNDG4YAjg2XP6d1eZvHuI\n" \
                            "YwNycKM4KcCB5suqEQJBAOJdR3jg0eHly2W+ODb11krwbQVOxuOwP3j2veie8tnk\n" \
                            "uTK3NfwmSlx6PSp8ZtABh8PcpRw+91j9/ecFZMHC6OkCQQC9HVV20OhWnXEdWspC\n" \
                            "/YCMH3CFxc7SFRgDYK2r1sVTQU/fTM2bkdaZXDWIZjbLFOb0U7/zQfVsuuZyGMFw\n" \
                            "dwmbAkBiDxJ1FL8W4pr32i0z8c8A66HumK+j1qfIWOrvqFt/dIudoqwqLNQtt25j\n" \
                            "xzwqg18yw5Rq5gP0cyLYPwfkv/BxAkAtLhnh5ezr7Hc+pRcXRAr27vfp7aUIiaOQ\n" \
                            "AwPavtermTnkxiuE1CWpw97CNHE4uUin7G46RnLExC4T6hgkrzurAkEAvRVFgcXT\n" \
                            "mcg49Ha3VIKIb83xlNhBnWVkqNyLnAdOBENZUZ479oaPw7Sl+N0SD15TgT25+4P6\n" \
                            "PKH8QE6hwC/g5Q==\n" \
                            "-----END RSA PRIVATE KEY-----\n",

                            "-----BEGIN RSA PRIVATE KEY-----\n" \
                            "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAID6jcWew5tz1JUj\n" \
                            "xkDBzfq7sPCxXpQ/JCnAw2CGLJOPtHRSOgEW8upxh38kIY/IXNlZAXzQ+YfsRDpz\n" \
                            "Gk0pp6j+ExLS7azopzZRXRIMj3teAAi3QD7jURQ1Nn8iPEdOwsCRPB3t5sESS1CJ\n" \
                            "3CrsPvN84kAJpZDvS4OY9S51wfLtAgMBAAECgYANeJ3oHx31FZMFhLgHOXbHEmV3\n" \
                            "rj7fovym88A0S69KNj81ywTN6lSy0erCB8cNmnLALMCwBa+aV74EkNMVbh1ZrHg3\n" \
                            "x0mHopZnH0JkeBBQ05zMFvX1AkaZ/m86rZt36HQRfiE7Np72xYxDpEI1hdtC6wIi\n" \
                            "UZFPMRC1JTJiD+gtrQJBAPbAC/ao4UVmApz9/vOad8UFEQVvI1oNxxtGxdWxe2SU\n" \
                            "wpBJaj12Y11a4h9hW8XgTioqIAGVf+xrPOiMDKmjaq8CQQCF0E5ZeI8yFQtAOfwB\n" \
                            "QPoGpmGBy0Y83sLVcxEeiQT9Sq3/pj6PLyBjx+ISvvWYHB7S/28RY6BGYtSDBnZY\n" \
                            "zrMjAkA7RANbmlKJNag5BvS+lAJiawYclQYbsiV5krUfz4JAtU5KE6gV3SKeoJ6h\n" \
                            "ROQjEe4USIvpdXwFT/iQLls4P4z3AkB/zXjXSSbyvViWigrfI7DoowYj0gKOZm+N\n" \
                            "L64dDN7AEBBpR90eIfN8eU65errUAZ+LBD2PTSipsQCo94YWwawjAkA+JHuJcLHk\n" \
                            "V7LIJ1nTQnok7fp9MJpKYZ6/yrFsslk6Z1ZP58TWi3OVj4VoMen+HUui7EKBI0oq\n" \
                            "kDtLB6UAhLPV\n" \
                            "-----END RSA PRIVATE KEY-----\n",

                            "-----BEGIN RSA PRIVATE KEY-----" \
                            "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAISlYw2jBEciXwhH\n" \
                            "BOKC9r6ou7CnBDww0KhaCrUw1QCrfrTnbrZiX/bWWq6HSux9Ll0jKP7H+sq77E19\n" \
                            "lekCduYGfzWv9OtQKF3P2aUHpyx9Lh51mtFx5VzxtUplWE/W3/Qs0iW3XOCKHqwF\n" \
                            "tzuKkI6DpdR4QFnUFDS+gKN5CSVbAgMBAAECgYBe4/2HTN4LkUAQqNWKwQuI+yZB\n" \
                            "ykkSUg2C0d8lHYjTENv0yDcATEHAUDnQ7sIfibG4OSXjleYIUAVMrhGm/fdVq+1u\n" \
                            "kHX/7LdBorCOERszDk8FMUMsdkXhkB0gPuSGWdVpXOs0kb0GDbd5CVJPYTf8cD/8\n" \
                            "OLt3C2cmmQ66WqiccQJBAOCYO3bEdQ1g46awPgEVFOujoQLzKg1BVGPn+W68ZGXW\n" \
                            "h6vi8T2jSU8rPLDlbzIQD4cTINEftohfZS5ccrv2hKMCQQCXMbB9/4pE8iz02wJA\n" \
                            "Fs5leDuxMkMgddbdQg1ecJnbEXR8JeH9sE8nhoBQddHD1yu900S4itw7Z+rbxCJb\n" \
                            "9a/pAkA9RyvKPtXU/Z9/RkzUjMT1eeKfZGsPzMhSreMvZHVcF8lSi4vYjmmdESXw\n" \
                            "+dh550nlR8HHbQincqevm4euYxdTAkBNvAdxEJRnlFfW4E9M4izl8KZIGX53zv5U\n" \
                            "reQvvRbtkhDgz51ckGxx9u478AeUeCmOJHQ9qW9Hv8r5iOLdgvkZAkABBIVTjCYk\n" \
                            "c8AiC99iaXSZL8iTa+ZT4CQzzSiOh8oNcHzl/szd7RU7nbiTPcJVEEhhGIXLJ237\n" \
                            "r+kkId8iRWZL\n" \
                            "-----END RSA PRIVATE KEY-----\n",

                            "-----BEGIN RSA PRIVATE KEY-----\n" \
                            "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJP62YnKMB4cNeo4\n" \
                            "jtPg+NED16Ah7n38ddcITHvN9qeZ+08PjwCCAveyxSljK/Y1ctLcUCm3hXeQxdIA\n" \
                            "bUgBAGecKbv+8qAhrYj7ag4m081b1/bd1iA5DNR0j5XKEbhrZBlzoam2zeP6EJh5\n" \
                            "Ean/SlfkrwhPgQ1AzvmM64lW5usjAgMBAAECgYBDtjD8X8wMuxPgjOiuAu9XlM6B\n" \
                            "s4URmQfC0UVOETygDFF2J8RjkxoQhXi6K2reSi60VaNIs3Ua9N/P6+oVXH/2M6rc\n" \
                            "7X+14KBtHhub/dDmGeLrKRNRCxlfdvh+6pIRucpSxvaun+l+Rt8Bt8eVtpVS9oSp\n" \
                            "5j4IVJvarb38QODfgQJBAOsezB9SX8J4Tnp9/p8kfSpBKK/c5NIjRWfJX1PMRXLp\n" \
                            "Pu1gD60l5s9B5xh5Kry9JbJMS5AQhaCj2xJgzH5Fg1MCQQChHwKmu00bGWJDYg4D\n" \
                            "8Ci662mmoL01T254giRFBd1oco0RbUvaZVC4x5XUwKzlX2RKs5gD1inV4UyhvK19\n" \
                            "YU7xAkBp7WgdPGl0HeuNeDI81J2nac/A244jtkxQpALUqBUp3jfBjiPB6G+CNLi+\n" \
                            "5+f/PGA9Ye4xK6BobSoHr6CxyvONAkAfoDalA57e8tyW3Whi3YEhL5RNYL/C9xR4\n" \
                            "ExOLeNs85T9LbGi3NavimUqPuEI3w8Gr6BSurBsKIG8qUB69vZwBAkEAwJpC8UrK\n" \
                            "ez7hOfeOqiS3fhc8I+w6oanC0IHBJFX2nR5wPujHDoNOVUXc61tZF9JnixAtophz\n" \
                            "0o6LFv5ucMwVOw==\n" \
                            "-----END RSA PRIVATE KEY-----\n",

                            "-----BEGIN RSA PRIVATE KEY-----\n" \
                            "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAKDBm2vlaZFYapdr\n" \
                            "pvF2pANSaP5dT68DjMrZvs1/OrirLXjfjny5/FeJ04yOhItU/cGrImBZqZ3Qphjt\n" \
                            "i3dsOYVtZqyGLt/45h1akM2LF3kC9wY47NCFKERn/RTPwIb+Bz32zDKyyfGzRgGD\n" \
                            "0eRrhaHS5/E7z0pICm4t6AsTmLX9AgMBAAECgYEAh4aRlCYFmQ50VpHgXYNLBK3u\n" \
                            "bDuYmRCiGsX18ONJSzStElFOm+JkVhyRJ9di8OBHSoYPZjFRKQYlcbCaOqUX3Ani\n" \
                            "8G2YgOBFkOo6qd1VZ3gji2S1UStPf2/3UsGPd8JPIALac6DBW10LLyoq1aPFU4++\n" \
                            "iBUR261xHYZKIwM+ZAECQQDOe/D+nRdTg+vYpDvaKrrPf50MrVz/VsKUR8augwlK\n" \
                            "m4Gdr3OY2e6SS8JdjLUDUDr4znOYM2Qdk6c/zzRoDAz9AkEAx05uvgyfTtDR0Jnn\n" \
                            "eCHHHPnR7s9wevWQv7+nIiSGV9sq4yE/d/2y4GBJfob6+QMEQet0QPDlNcLbj4t3\n" \
                            "rKQdAQJAeRxpdm5dyDaQlzl9gbGecSbAzzbAXWReLOsMtj9Vq9UaaYsHmpf5PwYA\n" \
                            "sy5c3dypOladpqA+ELsSVnMKohyvYQJBAJpQGeI/96CYgbsXTmZvELFYo7hZGGe7\n" \
                            "dgVgqFEBIpsncD9HYNLQtQyQwJacf/kI4uT/HpWhbnZ/lmu/ujsLHgECQQCyS++g\n" \
                            "YY9N0cah7NP+LhUydnSc7x+z4Tdyqai7EX5Gq7L6GdcHNh+B7OekE2SPADJyKZKo\n" \
                            "PpCcipiWRYyzU0cY\n" \
                            "-----END RSA PRIVATE KEY-----\n",

                            "-----BEGIN RSA PRIVATE KEY-----\n" \
                            "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKLhBchsUaog9aze\n" \
                            "BLSUI7MJUWALB0FTPNTjH7DiTPhriMSw5llmY9JCXc/Tff50MUawY5ayutgo6UYc\n" \
                            "A8sFK3Hlu3yxfSr8RZAHhwpdRF7j2ttdJnoZdFHnn9QVk0cSjp3oTaVLsymBBCz2\n" \
                            "N/rmm/cfSARsD2P0n5XLmvlteqYRAgMBAAECgYAlWf8OgDCWGCresqdXleU96HQd\n" \
                            "10mZpHH9y/v3f13xVg+uM3cPp1ha3ldPEowBLzohoM+lvmT0ryUXq9L+2rekb20Y\n" \
                            "PSuZQAwMxu36+Eigqke9fTfRWtMNCYlqGuZqin82qcK60p/xduoFnaI9KW7f4SlM\n" \
                            "iNjDk8Yq0aCjw6RysQJBAOmylIIwoXiL2usNeCaU0QpQseY7Ej9paxOtMbI1YDhr\n" \
                            "Gc9JjZE36jlFNAQv13kXBpGdJ6MzwZ0YrMK67ba0KvUCQQCybEmYnw72fl1sAnBc\n" \
                            "80xSkxMVOdG49Mb2/tqGpt3k0rSKxxFix1o2iJvYS9nZAGUUn2dnFEf4AZPAEK/7\n" \
                            "hRUtAkEApbtUoIN2b7PXG+zgcZQGL2eM0jbAOSI8oqan4LcDtt8VXbDO6daaj+To\n" \
                            "/7Mh/yj6Kpgl/RJ+UzelhS/l1zUsZQJAPpAB7mY3lO8SSwE/7RfSt1Gi61pu02/h\n" \
                            "JFKQxY5VWBsZ+196FSzZ0S1tmBZguNqOlwCd/WL7KVdEO6CeVI+BsQJABqF6MwMC\n" \
                            "2BQghMbCjc48ayUq+LgpFEPTvpjGDOfSosRf+1IoIBh180W1vR/GIfkK5jgEkIr8\n" \
                            "KypQOnTqJ6XFqg==\n" \
                            "-----END RSA PRIVATE KEY-----\n",

                            "-----BEGIN RSA PRIVATE KEY-----\n" \
                            "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKcJkdadgWpgH/qA\n" \
                            "l2Rzgw8NO0EnbSeQQB3e2xji08qzwxXjIiMlvkK2WtsoePM/WgP/UBCyPoQqUQwU\n" \
                            "gq1qQvHn5XJusxgT50N2QO14eZVfQB4XLDTTUXJBWW3UH45I09GxwojmyHUv9l3C\n" \
                            "eszLpLqc1tDk3mGWzqTaSA07mdDtAgMBAAECgYB/YaLf4blhn/CDHjFVn2lgvxxi\n" \
                            "8WgidbUPknXPIpuUx0WMmWvdFdlkEqBy5Qhnp/ZDeh5avTNDoumvpqyJBrIJfGHP\n" \
                            "WyvZVBi/wFsqJEBfGhi+GCdF6ehmn4yXqjLvChPCJF6nuzVW6nGZY8zAHx4Z7J6Q\n" \
                            "IE1aNGbjtDsJTj0JmQJBAPVlB+P+FDZw3c51jmdoeVjxdHxOkrcHPfuH1qPJljTK\n" \
                            "H55I8orfJqF/U/kxzZSdCU8Qh9iDUkQ1ti7GqhfKMNsCQQCuQZ5iXkhUVEC/wwo+\n" \
                            "wTSjyWFoRXiieyZUiKn5IqXhpBwlpQYGXT5KEe0AlZM1MfTCnFSMZOw3SkjgmVIg\n" \
                            "oivXAkA5s2HhmDLEglGFZFrxsb0mzs+nEwqogsluRYiQxqvNCeHZZCmzwbjhrIDg\n" \
                            "TXebhDlWH/rxTB+h7kdCRHBmW6KVAkAmJQMQsWbP3umVkJJLjmuBdvG1q49usdqA\n" \
                            "IrJicO0y6YOn0enxtrON70KcICHrQRY9C4+OdAEpUT+Gusk5j4ZdAkEAzRzjLUkT\n" \
                            "SEVdPs1kYrftWD0EznSogCFC02u4fo5n/4b7bWtaM/8YPZh7+a14f18LRo90s9IQ\n" \
                            "8QvQJmtQQwbkfA==\n" \
                            "-----END RSA PRIVATE KEY-----\n",

                            "-----BEGIN RSA PRIVATE KEY-----\n" \
                            "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKixRBNbBCtXocog\n" \
                            "SPXgxiS5g1KTPVPKZwA/l+jDY5iYZ0t0pN6UBuBfhWeKKsE7ZT56tPrflOdx2Xui\n" \
                            "7g2+WHa+UCVfAEBOCUrsvD7Tsoasgfmyah4m3ywDY9SFnmPUwXjQDjIoeF+H5IYj\n" \
                            "5kuqBiS4j4yWn9C+Tw4AntwQfeUJAgMBAAECgYBgkPkzS0rbtNJ87nZVqlJC+59d\n" \
                            "ScQ1jwvfbIf9SrxcwgF/hEpMz9gP4R5w4vsOmn2egofPhOWsh9PDnsU/QNNKV45N\n" \
                            "g3VMJ88d+xKPP2vnPypiEYpG0FWMkCMSkZYyDCdonx9dgF9iK3i6cqqHd/JJx+nb\n" \
                            "EDAfN9ByjMNnK1FZMQJBAOB3sGEUTVsex1XUCe36Rf3TE9V9ogPDucER3FJpk+/C\n" \
                            "D3sz7nZx+tq6YyT7YxUYSBe2s4bca5LNRCOBpMlNiPsCQQDAY8pwyYhaslsfkc1T\n" \
                            "loZtb92C4Ak1EJqk6Ywwar/iNCPgKp3hRED0fncYinzpzf8rNT+fUDbZybjZxVOQ\n" \
                            "f/LLAkEAxOcZOL+HcAQa1eZP44rkdNkBEAjJ40WBH6TcQQrOM8ZmsCuI5ivr4o0X\n" \
                            "xWwjqXCIZQzmhMm8L6WSPRdPhypVmwJAeDWiBykVZr4si6Q5bDIQWo7cFGtRtXNj\n" \
                            "fQlki9gXfwpfJDDcpyVThLEETzQw6pHJD0FdOHkRXLFbK87M8OvRUwJAUdxLwYPQ\n" \
                            "gohQGJ+1SmK29JwceBz75JYzVsdwPFglujIuul4uE2i2KrQUOT03HI9d9riWa2Ia\n" \
                            "7ZM/xGn/TvNRfQ==\n" \
                            "-----END RSA PRIVATE KEY-----\n",

                            "-----BEGIN RSA PRIVATE KEY-----\n" \
                            "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALIu4fiV8dhyYYwQ\n" \
                            "kDFsX1vpSIwRBWUDuMd/wpaYUP5j9vzTJwjopeSQlcBFJtc6UJpGxDUWQM6UWYpA\n" \
                            "BdmwrztFTgtXIAL1JPiMNLXT++LsZQi329ZSizQNf6a/mkUpY16XhF4DKbNDs+bS\n" \
                            "kGZcw/6FKsE1Uk58CgiraDCgsBBXAgMBAAECgYEApmTzryHPnFKMV7FsBktu7bT3\n" \
                            "g52tjPyhxOPBQsLw9+9ASi+hR0eDC+QdhFTPhbQ2ayvktLKYSJHu4BUToYvGxqHG\n" \
                            "0hiVzCYDn2rLyqmF0qoIz1shVb6/D0MF+WDw0rEjrGgn2TIXC3ZRom9hjscrD9JG\n" \
                            "6cj/lSj6lVM6OxaLdOkCQQDmtTrLxEHLxBG4gVydlZlxNW6AiEd1GVJOC/PXfW2L\n" \
                            "cehtdltyBCrLDlkO4cf/3aqcY+1pWS5hUGfInHIkesklAkEAxbeOOfNVMUKYL5tz\n" \
                            "DrwjCmQa4jArwiGOjILaGea93fDNdW80DBYapqEbu7Wew/46p8zN8wtf+bst1tSR\n" \
                            "mmtQywJBAOCIi0Obq0mMdo6yYBgCbAcRMI2plJoz3bWVzmjwarfnUYWPRmqOAbQE\n" \
                            "L8rbFRJBg3WXj40TPZ96aLeHA1PbqH0CQALsYNz4fRT6YBesG7pnC7mWm1Mm1S7M\n" \
                            "ojfvo1vornv+mHsZBtL67K/0B93xpIRPWPysKYtjaqrdmqLnh7OZzJsCQGpel/SU\n" \
                            "exXjt/62FguFIoaG0AmfPpmTjf2VNbCZUbl9NbtocHia4x9neUvk4veRnRBOBhA0\n" \
                            "bufxdFgODagc89s=\n" \
                            "-----END RSA PRIVATE KEY-----\n",

                            "-----BEGIN RSA PRIVATE KEY-----\n" \
                            "AAggJ3AgEAMA0GCSqGSIb3DQEBAQUABIICYTCCAl0CAQACgYEAnnSzZLcsra5clC\n" \
                            "wLzm4yrrW4CL2DiH6IQslmueTsQ0B/z2Ir6fDX+eZ9GFPWOi+C/4qw6A4XJiW4KD\n" \
                            "Xg3CuyPPT0ZqeQzs0RVQBMirBfgAVCHoKDNyvXnNATQkP7dE9w1m5n7nlZfbsBl4\n" \
                            "bYJUVL+mFiCiOYoQSPR3BXIuIGsZsCAwEAAQKBgCKuWDVLAjRhXVHw8gSUifNDQq\n" \
                            "xnDkrpptk3S4yUVkHB9DdnvUTOufawQ+D3OIQzsfBMYrvnmZl31/61DCokRjZJAL\n" \
                            "d/9HgkKnXhfILtFOsBLhi7J8wusllxOPkO0Z9np++EqEQCofcKe4AlqXMRHLlDRn\n" \
                            "wLJWgUFD5fRsoCiWRBAkEA06+D/uYtSj/pKCSiUH7GAucHhf+y2NtOyl44xVC15n\n" \
                            "gU2/JSdQ79urXmJdd11Kop+M0+bvCIGEGLu9kfWR5ArQJBAL+gih/1KLW+QKe2LZ\n" \
                            "fZcYMfFtI9/v8zjqMBPVOkotTHzFdaeEVKeFrFb2UdXt4laZvXxUBo7qJpGk2+PZ\n" \
                            "8e3GcCQAE/LWXY8TdYvQTRgms68+ucdLzjTqhcUlB60ZbH7OpYlrbc7INn/TKWU6\n" \
                            "6xYC5KekjO3KlGnWaXLD2E/9xEg1kCQQCzmpN7SnuChDPzPQPUrCABJnVsTmEe7k\n" \
                            "LFMtc4+zkGt9ElGo1ZXGgbo6s5mWKeUXB/eafOK8tme54EucblybYHAkEAnu6ww6\n" \
                            "KZoqmX3MIEUt2PbkArfztWBiNxxAqfie7undBg7VtP+ClhOB3iqO/rCGsLIvSzhl\n" \
                            "Sqo5g7m+TLGDmNcw\n" \
                            "-----END RSA PRIVATE KEY-----\n"
                            };
    };
}

#endif // PCAPFS_CS_MANAGER_H
