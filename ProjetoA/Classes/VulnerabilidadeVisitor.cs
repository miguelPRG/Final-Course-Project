using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.UI.Xaml.Shapes;
using Microsoft.CodeAnalysis;
using Windows.System;
using Windows.UI.Xaml.Controls;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Windows.Media.Devices;
using System.Xml.Linq;
using System.Diagnostics;
using FuzzySharp;
using System.Threading;
using Windows.UI.Xaml.Controls.Primitives;
using System.Reflection.Metadata;
using System.Collections;
using Windows.UI.Composition.Interactions;
using Windows.Networking.Sockets;
using System.Net;
using Windows.Services.Maps;

/*A FAZER: 
 
 A função que determina a precisão entre a string e a expressão Regex não está a funcionar corretamente
 
 */

namespace Projeto.Classes
{
    public enum NivelRisco
    {
        Alto,
        Medio,
        Baixo
    }

    public class VulnerabilidadeVisitor
    {
        //Lista de vulnerabilidades encontradas
        private List<(string Tipo, int Linha, string Codigo, NivelRisco NivelRisco)> vulnerabilidadesEncontradas;

        //Diciónário utilizado para testar as vulnerabilidades encontradas
        Dictionary<string, string[][]> dados_teste;

        //Lista que guarda palavras reservadas para cada tipo de vulnerabilidade
        Dictionary<string, Dictionary<string, int>> padroes;

        int falsos_positivos = 0;
        int verdadeiros_positivos = 0;

        public VulnerabilidadeVisitor()
        {
            vulnerabilidadesEncontradas = new List<(string, int, string, NivelRisco)>();
            dados_teste = new Dictionary<string, string[][]>();
            padroes = new Dictionary<string, Dictionary<string, int>>();

            //SQL
            padroes["Possível Injeção de SQL"] = new Dictionary<string, int>
            {
                { "select",0},
                { "insert",1},
                { "update",2},
                { "delete",3},
                //{ "create",4},
                //{ "alter",5},
                //{ "drop",6},
            };
            dados_teste["Possível Injeção de SQL"] = new string[3][];
            dados_teste["Possível Injeção de SQL"][(int)NivelRisco.Alto] = new string[]
            {
                // Expressões Regulares para alto risco
               "string query = \"select * from users where username = '{userinput}'\";",
               "string query = \"insert into tabela (colunas) values ('\" + userinput + \"')\";",
               "string query = \"update tabela set coluna1 = 'valor' where coluna2 = '\" + userinput + \"'\"",
               "string query = \"delete from tabela where coluna= '\" + userinput + \"'\"",
            };
            dados_teste["Possível Injeção de SQL"][(int)NivelRisco.Medio] = new string[]
            {
                // Expressões Regulares para médio risco
                 "string query = \"select * from users where username = @username\";",
                 "string query = \"insert into tabela (colunas) values (@parametro)\";",
                 "string query = \"update tabela set coluna1 = 'valor' where coluna2 = @valor;\"",
                 "string query = \"delete from tabela where coluna = @valor\"",

            };
            dados_teste["Possível Injeção de SQL"][(int)NivelRisco.Baixo] = new string[]
            {
                // Expressões Regulares para baixo risco
                "string query = \"select * table tabela;\"",
                "string query = \"insert into tabela (colunas) values ('');\"",
                "string query = \"update tabela set coluna1 = 'valor1' where coluna2 = 'valor2';\"",
                "string query = \"delete from tabela where coluna= 'valor'\"",
            };

            //Client XSS
            padroes["Possível Cliente XSS"] = new Dictionary<string, int>
            {
                { "<script>", 0 },
                { "<img>", 1 },
                { "<iframe>", 2 },
                { "<object>", 3 },
                // Adicione outras palavras reservadas conforme necessário
            };

            dados_teste["Possivel Cliente XSS"] = new string[3][];
            dados_teste["Possivel Cliente XSS"][(int)NivelRisco.Alto] = new string[]
            {
                // Expressões Regulares para alto risco
                "",
                "string userinput = \"<img src='\" + userinputfromuser + \"' onload='alert(\\\"xss attack\\\")' />\";",
                "string userinput = \"<img src=\\\"x\\\" onerror=\\\"alert('XSS')\\\" />\";",
                "string userinput = \"<object data=\\\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnZG9jdW1lbnQucGhwJyk8L3NjcmlwdD4=\\\"></object>\";"
            };
            dados_teste["Possivel Cliente XSS"][(int)NivelRisco.Medio] = new string[]
            {
                // Expressões Regulares para médio risco
                "string userinput = $\"<div><script>alert('xss ataque!');</script>\"</div>\";",
                "string userinput = \"<img src=\\\"javascript:alert('xss')\\\" />\";",
                "string usercontent = \"<script>document.write(\\\"<iframe src='http://www.example.com'></iframe>\\\");</script>\";",
                "string userinput = \"<object data=\\\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=\\\"></object>\";",

            };
            dados_teste["Possivel Cliente XSS"][(int)NivelRisco.Baixo] = new string[]
            {
                // Expressões Regulares para baixo risco
               "string userinput = \"<script>alert('xss ataque!');</script>\";",
               "string userinput = \"<img src=\\\"http://example.com\\\" />\";",
               "string usercontent = \"<iframe src='http://www.example.com'></iframe>\";",
               "string userinput = \"<object data=\\\"javascript:alert('xss')\\\"></object>\";"
            };

            //Hardcoded Password
            /*palavrasReservadas["Possível Password Fraca"] =new string[]
        {
            {"123456", 0},
            {"password", 0},
            {"123456789", 0},
            {"12345678", 0},
            {"12345", 0},
            {"1234567", 0},
            {"1234567890", 0},
            {"qwerty", 0},
            {"123123", 0},
            {"admin", 0},
            {"abc123", 0},
            // Adicione outras senhas conhecidas conforme necessário
        };
            dados_teste["Possível Password Fraca"] = new string[]
            {

            };*/

            //Target Blank
            padroes["Possível Target Blank"] = new Dictionary<string, int>
            {
                { "_blank",0 },
            };

            dados_teste["Possível Target Blank"] = new string[3][];
            dados_teste["Possível Target Blank"][(int)NivelRisco.Alto] = new string[]
            {
                // Expressões Regulares para alto risco
                "string link = \"<a href='\" + userInput + \"' target='_blank'>link</a>\";",
            };
            dados_teste["Possível Target Blank"][(int)NivelRisco.Medio] = new string[]
            {
                // Expressões Regulares para médio risco
                "string link = \"<a href='\" + userInput + \"' target='_blank'>link</a>\";",
            };
            dados_teste["Possível Target Blank"][(int)NivelRisco.Baixo] = new string[]
            {
                // Expressões Regulares para baixo risco
                "string link = \"<a href='http://exemplo.com' target='_blank'>link</a>\";"
            };

            //Cookies
            padroes["Possiveis Cookies não Protegidos"] = new Dictionary<string, int>
            {
                //{ "expires",0 },
                { "max-age",0 },
                { "domain",1 },
                { "path",2 },
                { "set-cookie",3 },
                //{ "httpcookie",4 },
                { "httpcontext",4 },

            // Adicione outras palavras reservadas conforme necessário
            };
            dados_teste["Possiveis Cookies não Protegidos"] = new string[3][];
            dados_teste["Possiveis Cookies não Protegidos"][(int)NivelRisco.Alto] = new string[]
            {
                // Expressões Regulares para alto risco               
                "response.cookies.append(\"password\", \"secretpassword\", new cookieoptions { maxage = timespan.fromdays(365) });\r\n",
                "response.cookies[\"session\"].value = \"1234\"; response.cookies[\"session\"].domain = Request.headers[\"host\"];\r\n",
                "response.cookies.add(new httpcookie(\"nome\", \"valor\") { path = request.url.absolutepath });\r\n",
                "response.headers.add(\"set-cookie\", $\"user_token={usertoken}; samesite=none; secure; httponly\");\r\n",
                "httpcontext.current.request.cookies[\"nomecookie\"].value;\r\n"
            };
            dados_teste["Possiveis Cookies não Protegidos"][(int)NivelRisco.Medio] = new string[]
            {
                // Expressões Regulares para médio risco              
                "response.cookies.append(\"userid\", \"9876\", new cookieoptions { maxage = timespan.fromdays(1) });\r\n",
                "response.cookies[\"session\"].value = \"1234\"; response.cookies[\"session\"].domain = request.url.host;\r\n",
                "response.cookies.add(new httpcookie(\"nome\", \"valor\") { path = \"/restrito\" });\r\n",
                "response.headers.add(\"set-cookie\", $\"session_id={usersessionId}; secure\");\r\n",
                "httpcontext.current.response.cookies.add(new httpcookie(\"nomecookie\", \"valor\"));\r\n"
            };
            dados_teste["Possiveis Cookies não Protegidos"][(int)NivelRisco.Baixo] = new string[]
            {
                // Expressões Regulares para baixo risco
                "response.cookies.append(\"sessionid\", \"12345\", new cookieoptions { maxage = timeSpan.fromminutes(30) });\r\n",
                "response.cookies[\"session\"].value = \"1234\"; response.cookies[\"session\"].domain = \".example.com\";\r\n",
                "response.cookies.add(new httpcookie(\"nome\", \"valor\") { path = \"/\" });\r\n",
                "response.headers.add(\"set-cookie\", \"user_id=123\");\r\n",
                "httpcontext.current.response.cookies[\"nomecookie\"].value = \"valor\";\r\n"
            };

            //CSP Header
            padroes["Possivel CSP Header"] = new Dictionary<string, int>
            {
                {"script-src",0 },
                {"base-uri",1},
                {"form-action",2},
                {"frame-ancestors",3},
                {"plugin-types",4},
                {"upgrade-insecure-requests",5},
                {"block-all-mixed-content",6},
            };

            dados_teste["Possivel CSP Header"] = new string[3][];
            dados_teste["Possivel CSP Header"][(int)NivelRisco.Alto] = new string[]
            {
                "response.headers.add(\"content-security-policy\", \"script-src 'none' 'unsafe-inline' 'unsafe-eval'\");\r\n",
                "response.headers.add(\"content-security-policy\", \"base-uri 'none';\");\r\n",
                "response.headers.add(\"content-security-policy\", \"form-action 'none'\");\r\n",
                "response.headers.add(\"content-security-policy\", \"frame-ancestors 'none'\");\r\n",
                "response.headers.add(\"content-security-policy\", \"plugin-types application/pdf\");\r\n",
                "response.headers.add(\"content-security-policy\", \"default-src 'none'; upgrade-insecure-requests\");\r\n",
                "response.headers.add(\"content-security-policy\", \"default-src 'none' https:; block-all-mixed-content\");\r\n"
            };
            dados_teste["Possivel CSP Header"][(int)NivelRisco.Medio] = new string[]
            {
                "response.headers.add(\"content-security-policy\", \"script-src 'self' https://cdn.example.com\");\r\n",
                "response.headers.add(\"content-security-policy\", \"base-uri 'self' https://dominio-permitido.com\");\r\n",
                "response.headers.add(\"content-security-policy\", \"form-action 'self' https://trusted-domain.com\");\r\n",
                "response.headers.add(\"content-security-policy\", \"frame-ancestors 'self' https://trusted-domain.com\");\r\n",
                "response.headers.add(\"content-security-policy\", \"plugin-types application/pdf application/zip\");\r\n",
                "response.headers.add(\"content-security-policy\", \"default-src 'self'; upgrade-insecure-requests\");\r\n",
                "response.headers.add(\"content-security-policy\", \"default-src 'self' https:; block-all-mixed-content\");\r\n"
            };
            dados_teste["Possivel CSP Header"][(int)NivelRisco.Baixo] = new string[]
            {
                "response.headers.add(\"content-security-policy\", \"script-src 'self'\");\r\n",
                "response.headers.add(\"content-security-policy\", \"base-uri 'self'\");\r\n",
                "response.headers.add(\"content-security-policy\", \"form-action 'self'\");\r\n",
                "response.headers.add(\"content-security-policy\", \"frame-ancestors 'self'\");\r\n",
                "response.headers.add(\"content-security-policy\", \"plugin-types *\");\r\n",
                "response.headers.add(\"content-security-policy\", \"upgrade-insecure-requests\");\r\n",
                "response.headers.add(\"content-security-policy\", \"block-all-mixed-content\");\r\n"
            };

            // Iframe 
            padroes["Possivel Uso de Iframe sem SandBox"] = new Dictionary<string, int>
         {
            {"iframe",0},
            {"sandbox",0}
             // Adicione outras palavras reservadas conforme necessário
         };

            dados_teste["Possivel Uso de Iframe sem SandBox"] = new string[3][];
            dados_teste["Possivel Uso de Iframe sem SandBox"][(int)NivelRisco.Alto] = new string[]
            {
                // Expressões Regulares para alto risco
                @"<iframe\s+src\s*=\s*"".*""\s*>",
                @"<sandbox\s+src\s*=\s*"".*""\s*"
            };
            dados_teste["Possivel Uso de Iframe sem SandBox"][(int)NivelRisco.Medio] = new string[]
            {
                // Expressões Regulares para médio risco
                @"<iframe\b[^>]*>",
                @"<sandbox\b[^>]*>",
            };
            dados_teste["Possivel Uso de Iframe sem SandBox"][(int)NivelRisco.Baixo] = new string[]
            {
                // Expressões Regulares para baixo risco
                @"\biframe\b",
                @"\bsandbox\b"
            };

            // JQuery
            /*padroes["Possivel JQuery"] = new Dictionary<string, int>
            {
                {"document",0},
                {"function",1},
                {"ajax",2},
                {"post",3},
                 // Adicione outras palavras reservadas conforme necessário
             };

            dados_teste["Possivel JQuery"] = new string[3][];
            dados_teste["Possivel JQuery"][(int)NivelRisco.Alto] = new string[]
            {
              
            };
            dados_teste["Possivel JQuery"][(int)NivelRisco.Medio] = new string[]
            {
                
            };
            dados_teste["Possivel JQuery"][(int)NivelRisco.Baixo] = new string[]
            {
               // Expressões Regulares para baixo risco
                @"\bdocument\b",
                @"\bfunction\b",
                @"\bajax\b",
                @"\bpost\b",
            };*/

            // Domain
            /*palavrasReservadas["Possivel Domínio Fraco"] = new string[]
            {
                "localhost",
                "127.0.0.1",
                "example.com",
                "example.net",
                "example.org",
                "localhost.localdomain",
            // Adicione outros domínios hardcoded conforme necessário
            };
            dados_teste["Possivel Domínio Fraco"] = new string[]
            {

            };*/

            //DOM Open Redirect
            /*padroes["Possivel Redirecionamento de Domínio"] = new Dictionary<string, int>
            {
                {"window.location",0},
                {"document.location",1},
                {"document.url",2},
                {"location.href",3},
                {"location.replace",4},
                {"location.assign",5},
                 // Adicione outras palavras reservadas conforme necessário
            };

            dados_teste["Possivel Redirecionamento de Domínio"] = new string[3][];
            dados_teste["Possivel Redirecionamento de Domínio"][(int)NivelRisco.Alto] = new string[]
            {
                
            };
            dados_teste["Possivel Redirecionamento de Domínio"][(int)NivelRisco.Medio] = new string[]
            {
               
            };
            dados_teste["Possivel Redirecionamento de Domínio"][(int)NivelRisco.Baixo] = new string[]
            {
               
            };*/

            //Chaves de Criptografia
            /*palavrasReservadas["Possivel Fragilidade de Chave de Criptografia"] = new string[]
            {
            "aes",
            "des",
            "rsa",
            "sha",
            "md5",
            "hmac",
            "pbkdf2",
            "blowfish",
            "twofish",
            // Adicione outras palavras reservadas conforme necessário
            };
            dados_teste["Possivel Fragilidade de Chave de Criptografia"] = new string[]
            {

            };*/

            //Privacy Violation
            /*palavrasReservadas["Possivel Violação de Privacidade"] = new string[]
            {
            "breach",
            "leak",
            "expose",
            "hack",
            "exploit",
            "infiltrate",
            "compromise",
            "intrude",
            "access",
            "steal",
            "phishing",
            "identity theft",
            // Adicione outras palavras reservadas conforme necessário
            };
            dados_teste["Possivel Violação de Privacidade"] = new string[]
            {

            };*/


            //Path
            padroes["Possivel Caminho Transversal"] = new Dictionary<string, int>
         {
            { "c:\\",0},
            { "d:\\",1},
            { "e:\\",2},
             // Adicione outros caminhos e diretórios conforme necessário
         };

            dados_teste["Possivel Caminho Transversal"] = new string[3][];
            dados_teste["Possivel Caminho Transversal"][(int)NivelRisco.Alto] = new string[]
            {
                "c:\\\\(?:\\.\\.|[^\\\\]+)*(?:\\\\|$)",
                "d:\\\\(?:\\.\\.|[^\\\\]+)*(?:\\\\|$)",
                "e:\\\\(?:\\.\\.|[^\\\\]+)*(?:\\\\|$)",
            };
            dados_teste["Possivel Caminho Transversal"][(int)NivelRisco.Medio] = new string[]
            {
                "c:\\\\(?:[^\\\\]+\\\\)*[^\\\\]+",
                "d:\\\\(?:[^\\\\]+\\\\)*[^\\\\]+",
                "e:\\\\(?:[^\\\\]+\\\\)*[^\\\\]+",
            };
            dados_teste["Possivel Caminho Transversal"][(int)NivelRisco.Baixo] = new string[]
            {
                "c:\\\\[^\\\\]+",
                "d:\\\\[^\\\\]+",
                "e:\\\\[^\\\\]+",
            };

            // HSTS Header
            /*padroes["Possivel HSTS Header"] = new Dictionary<string, int>
            {
                { "strict-transport-security", 0},
                { "max-age", 1},
                { "preload", 2},
                 // Adicione outras palavras reservadas conforme necessário
            };

            dados_teste["Possivel HSTS Header"][(int)NivelRisco.Alto] = new string[]
            {
                // Expressões Regulares para alto risco
                @"response.addheader\(""strict-transport-security"",\s*"".*""\)",
                @"response.headers\.add\(""strict-transport-security"",\s*"".*""\)",
                @"httpcontext.current.response.addheader\(""strict-transport-security"",\s*"".*""\)"
            };
            dados_teste["Possivel HSTS Header"][(int)NivelRisco.Medio] = new string[]
            {
                // Expressões Regulares para médio risco
                @"response.addheader\(""max-age"",\s*\d+\)",
                @"response.headers\.Add\(""max-age"",\s*\d+\)",
                @"httpcontext.current.response.addheader\(""max-age"",\s*\d+\)"
            };
            dados_teste["Possivel HSTS Header"][(int)NivelRisco.Baixo] = new string[]
            {
                // Expressões Regulares para baixo risco
                @"response.addheader\(""preload"",\s*"".*""\)",
                @"response.headers\.add\(""preload"",\s*"".*""\)",
                @"httpcontext.current.response.addheader\(""preload"",\s*"".*""\)"
            };*/

            //CSRF
            /*padroes["Possivel Vulnerabilidade CSRF"] = new string[]
             {
             "csrf_token",
             "csrftoken",
             "csrf_token",
             "anti_csrf_token",
             "csrfmiddlewaretoken",
             "__requestverificationtoken",
             // Adicione outras palavras reservadas conforme necessário
             };
             dados_teste["Possivel Vulnerabilidade CSRF"] = new string[] 
             {

             }*/

            //Heap Inspection
            /*palavrasReservadas["Possivel Heap Inspection"] = new string[]
            {
                "malloc",
                "calloc",
                "realloc",
                "free",
                "new",
                "delete"    ,
            // Adicione outras palavras reservadas conforme necessário
            };
            dados_teste["Possivel Heap Inspection"] = new string[]
            {

            }*/

        }

        public List<(string Tipo, int Linha, string Codigo, NivelRisco NivelRisco)> VulnerabilidadesEncontradas
        {
            get { return vulnerabilidadesEncontradas; }
        }

        public int getPrecision()
        {
            try
            {
                return (verdadeiros_positivos / verdadeiros_positivos + falsos_positivos) * 100;
            }

            catch (DivideByZeroException)
            {
                return 0;
            }
        }

        static bool ContemUmaPalavra(string input, Dictionary<string, int> conjunto, out int value)
        {
            foreach (var palavra in conjunto.Keys)
            {
                if (input.IndexOf(palavra, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    value = conjunto[palavra];
                    return true;
                }
            }
            value = -1;
            return false;
        }



        public void Visit(string[] code,int linhasIgnoradas) //Tempo de Compexidade: O(30n) <=> O(n)                                                                                                                               
        {
            for(int i = 0; i<code.Count(); i++)
            {
                foreach (var nome in padroes.Keys)
                {
                    int linha = i+1;

                    if(linhasIgnoradas>0)
                    {
                        linha += linhasIgnoradas -2;
                    }

                    AnalisarVulnerabilidade(code[i], linha ,padroes[nome], nome);
                }
                
            }

        }

        private void AnalisarVulnerabilidade(string code, int linha ,Dictionary<string, int> palavras, string nomeVulnerabilidade)
        {
            if (ContemUmaPalavra(code, palavras, out int value))
            {
                string min = code.ToLower();

                //Este array guarda a precisão dos dados de teste correspondentes à vulnerabilidade encontrada para diferentes niveis de risco
                double[] precisao = {
                    CalculateSimilarity(min,dados_teste[nomeVulnerabilidade][(int)NivelRisco.Alto][value])* 100,
                    CalculateSimilarity(min,dados_teste[nomeVulnerabilidade][(int)NivelRisco.Medio][value])* 100,
                    CalculateSimilarity(min,dados_teste[nomeVulnerabilidade][(int)NivelRisco.Baixo][value])*100
                };

                //Qual o nivel de risco mais provavel da vulnerabilidade encontrada
                int index = Array.IndexOf(precisao, precisao.Max());

                if (Math.Round(precisao[index]) >= 50)
                {
                    AdicionarVulnerabilidade(nomeVulnerabilidade, linha,code, (NivelRisco)index);
                    verdadeiros_positivos++;
                }

                else falsos_positivos++;

            }
        }

        private void AdicionarVulnerabilidade(string nomeVulnerabilidade, int linha ,string code, NivelRisco nivelRisco)
        {
            vulnerabilidadesEncontradas.Add((nomeVulnerabilidade,linha, code, nivelRisco));
        }
        //PREFERENCIALMENTE. Tenta utilizar estes métodos para determinar precisão:

        static double CalculateSimilarity(string str1, string str2)
        {
            int maxLength = Math.Max(str1.Length, str2.Length);
            if (maxLength == 0)
            {
                return 1.0; // Strings vazias são consideradas 100% semelhantes
            }

            int distance = ComputeLevenshteinDistance(str1, str2);
            return (1.0 - (double)distance / maxLength);
        }
        static int ComputeLevenshteinDistance(string s, string t)
        {
            int n = s.Length;
            int m = t.Length;
            int[,] d = new int[n + 1, m + 1];

            if (n == 0)
            {
                return m;
            }

            if (m == 0)
            {
                return n;
            }

            for (int i = 0; i <= n; i++)  // Corrected semicolon placement
            {
                d[i, 0] = i;
            }
            for (int j = 0; j <= m; j++)
            {
                d[0, j] = j;
            }

            for (int i = 1; i <= n; i++)
            {
                for (int j = 1; j <= m; j++)
                {
                    int cost = (t[j - 1] == s[i - 1]) ? 0 : 1;
                    d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
                }
            }
            return d[n, m];
        }
    }
}
