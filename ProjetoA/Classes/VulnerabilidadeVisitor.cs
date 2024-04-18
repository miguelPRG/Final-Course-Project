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
using Windows.ApplicationModel.Contacts;
using System.Security.Cryptography;

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

    public class Vulnerabilidade
    {
        public string Tipo { get; set; }
        public string Codigo { get; set; }
        public NivelRisco Risco { get; set; }

        public Vulnerabilidade(string tipo,string codigo, NivelRisco risco)
        {
            this.Tipo = tipo;
            this.Codigo = codigo;
            this.Risco = risco;
        }
    }

    public class VulnerabilidadeVisitor
    {
        //Lista de vulnerabilidades encontradas
        private List<(Vulnerabilidade Vulnerabilidade,List<int> Linhas)> vulnerabilidadesEncontradas;

        //Lista que guarda palavras reservadas para cada tipo de vulnerabilidade
        Dictionary<string, Dictionary<string, int>> padroes;

        //Diciónário utilizado para testar as vulnerabilidades encontradas
        Dictionary<string, string[][]> dados_teste;

        double falsos_positivos = 0;
        double verdadeiros_positivos = 0;

        public VulnerabilidadeVisitor()
        {
            vulnerabilidadesEncontradas = new List<(Vulnerabilidade Vulnerabilidade, List<int> Linhas)>();
            dados_teste = new Dictionary<string, string[][]>();
            padroes = new Dictionary<string, Dictionary<string, int>>();

            //SQL
            padroes["Possível Injeção de SQL"] = new Dictionary<string, int>
            {
                { "select",0},
                { "insert",1},
                { "update",2},
                { "delete",3},
                { "drop",4},
                //{ "create",4},
                //{ "alter",5},
                //{ "drop",6},
            };
            dados_teste["Possível Injeção de SQL"] = new string[3][];
            dados_teste["Possível Injeção de SQL"][(int)NivelRisco.Alto] = new string[]
            {
                // Expressões Regulares para alto risco
               "string consulta = \"select * from usuarios where username = '\" + username + \"' and password = '\" + password + \"'\";",
               "string query = \"insert into tabela (colunas) values ('\" + userinput + \"')\";",
               "string query = \"update tabela set coluna1 = 'valor' where coluna2 = '\" + userinput + \"'\";",
               "string query = \"delete from tabela where coluna= '\" + userinput + \"'\";",
               "string query = \"drop table tabela\";",
            };
            dados_teste["Possível Injeção de SQL"][(int)NivelRisco.Medio] = new string[]
            {
                // Expressões Regulares para médio risco
                 "string query = \"select * from users where username = '{userinput}'\";",
                 "string query = \"insert into tabela (colunas) values (@parametro)\";",
                 "string query = \"update tabela set coluna1 = 'valor' where coluna2 = @valor;\"",
                 "string query = \"delete from tabela where coluna = @valor\"",
                 null,
            };
            dados_teste["Possível Injeção de SQL"][(int)NivelRisco.Baixo] = new string[]
            {
                // Expressões Regulares para baixo risco
                "string query = \"select * table tabela;\"",
                "string query = \"insert into tabela (colunas) values ('');\"",
                null,
                "string query = \"delete from tabela where coluna= 'valor'\"",
                null,
            };

            //Client XSS
            padroes["Possível Cliente XSS"] = new Dictionary<string, int>
        {
            { "<script>", 0 },
            { "<img src=", 1 },
            { "<iframe src=", 2 },
            { "<object data=", 3 },
            // Adicione outras palavras reservadas conforme necessário
        };
            dados_teste["Possível Cliente XSS"] = new string[3][];
            dados_teste["Possível Cliente XSS"][(int)NivelRisco.Alto] = new string[]
            {
                // Expressões Regulares para alto risco
                null,
                "string userinput = \"<img src='\" + userinputfromuser + \"' onload='alert(\\\"xss attack\\\")' />\";",
                "string userinput = \"<iframe src=\\\"http://www.example.com\\\"></iframe>\";",
                "string userinput= \"<object data =\\\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=\\\"></object>\";",
            };
            dados_teste["Possível Cliente XSS"][(int)NivelRisco.Medio] = new string[]
            {
                // Expressões Regulares para médio risco
                null,
                "string userinput = \"<img src=\\\"javascript:alert('XSS')\\\">\";",
                "string userinput = \"<script>document.write(\\\"<iframe src=\\\\\\\"http://www.example.com\\\\\\\"></iframe>\\\");</script>\\\"\";",
                null
            };
            dados_teste["Possível Cliente XSS"][(int)NivelRisco.Baixo] = new string[]
            {
                // Expressões Regulares para baixo risco
                "string userinput = \"<script>alert('xss ataque!');</script>\";",
                "string userinput = \"<img src=\\\"http://example.com\\\"/>\";",
                "string userinput = \"<iframe src=\\\"http://www.example.com\\\"></iframe>\";",
                "string userinput = \"<object data=\\\"javascript:alert('xss')\\\"></object>\";",
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
                { "target=\\\"_blank\\\"",0 }
            };
            dados_teste["Possível Target Blank"] = new string[3][];
            dados_teste["Possível Target Blank"][(int)NivelRisco.Alto] = new string[]
            {
                // Expressões Regulares para alto risco
                "string link = $\"<a href=\\\"http://www.example.com/?user={userId}\\\" target=\\\"_blank\\\">Link Externo</a>\";",
            };
            dados_teste["Possível Target Blank"][(int)NivelRisco.Medio] = new string[]
            {
                // Expressões Regulares para médio risco
                "string linkhtml = $\"<a href='{userurl}' target='_blank'>link personalizado</a>\";",
            };
            dados_teste["Possível Target Blank"][(int)NivelRisco.Baixo] = new string[]
            {
                // Expressões Regulares para baixo risco
                "string link=\"<a href=\"https://www.example.com\" target=\"_blank\">link externo</a>\""
            };

            //Cookies
            /*padroes["Possiveis Cookies não Protegidos"] = new Dictionary<string, int>
            {
                {"httpcookie",0 },
                {"httpcontext",1 },
                {"set-cookie",2 },
                {"samesite",3 },

            // Adicione outras palavras reservadas conforme necessário
            };
            dados_teste["Possiveis Cookies não Protegidos"] = new string[3][];
            dados_teste["Possiveis Cookies não Protegidos"][(int)NivelRisco.Alto] = new string[]
            {
                "",
                "\"string valordocookie = httpcontext.current.request.querystring[\\\"valor\\\"];\",",
                "response.setcookie(new httpcookie(\"meucookie\", valor) { secure = true, httponly = true });",
                "cookie.sameSite = samesitemode.none;",

            };
            dados_teste["Possiveis Cookies não Protegidos"][(int)NivelRisco.Medio] = new string[]
            {
               "httpcookie cookie = new httpcookie(\"usuarioid\", usuario.id.tostring());",
               "httpcontext.current.response.cookies.add(cookie);",
               "response.setcookie(new sttpcookie(\"meucookie\", \"valor\") { secure = true });",
               "cookie.samesite = samesitemode.lax;",
            };
            dados_teste["Possiveis Cookies não Protegidos"][(int)NivelRisco.Baixo] = new string[]
            {
               "httpcookie cookie = new httpcookie(\"meucookie\", \"valordocookie\");",
               "",
               "response.setcookie(new httpcookie(\"meucookie\", \"valor\") { httponly = true });",
               "cookie.SameSite = samesitemode.strict;"
            };*/

            //CSP Header
            /*padroes["Possivel CSP Header"] = new Dictionary<string, int>
            {
                {"style-src",0 },
                {"default-src",1 },
                {"frame-src",2 },
                {"object-src",3 },
                {"child-src",4 },
                {"form-action",5 },
                {"plugin-types",6 },
            };

            dados_teste["Possivel CSP Header"] = new string[3][];
            dados_teste["Possivel CSP Header"][(int)NivelRisco.Alto] = new string[]
            {
                "response.addheader(\"content-security-policy\", \"style-src *\");",
                "response.addheader(\"content-security-policy\", \"default-src *\");",
                "response.addheader(\"content-security-policy\", \"frame-src *\");\r\n",
                "response.addheader(\"content-security-policy\", \"object-src *\");",
                "response.addheader(\"content-security-policy\", \"child-src *\");",
                "response.addheader(\"content-security-policy\", \"form-action 'none';\");",
                "response.addheader(\"content-security-policy\", \"plugin-types *\");"
            };
            dados_teste["Possivel CSP Header"][(int)NivelRisco.Medio] = new string[]
            {
                "response.addheader(\"content-security-policy\", \"style-src 'self' https://cdn.example.com\");",
                "response.addheader(\"content-security-policy\", \"default-src 'self' https://cdn.example.com\");",
                "response.addheader(\"content-security-policy\", \"frame-src 'self' https://cdn.example.com\");",
                "response.addheader(\"content-security-policy\", \"object-src 'self' https://cdn.example.com\");",
                "response.addheader(\"content-security-policy\", \"child-src 'self' https://cdn.example.com\");",
                "response.addheader(\"content-security-policy\", \"form-action 'self' data:;\");",
                "response.addheader(\"content-security-policy\", \"plugin-types application/pdf application/vnd.ms-excel\");\r\n"

            };
            dados_teste["Possivel CSP Header"][(int)NivelRisco.Baixo] = new string[]
            {
                "response.addheader(\"content-security-policy\", \"style-src 'self'\");",
                "response.addheader(\"content-security-policy\", \"default-src 'self'\");",
                "response.addheader(\"content-security-policy\", \"frame-src 'self'\");",
                "response.addheader(\"content-security-policy\", \"object-src 'self'\");",
                "response.addheader(\"content-security-policy\", \"child-src 'self'\");",
                "response.addheader(\"content-security-policy\",\"form-action 'self'\");",
                "response.addheader(\"content-security-policy\", \"plugin-types application/pdf\");"
            };*/

            // Iframe 
            /*padroes["Possivel Uso de Iframe sem SandBox"] = new Dictionary<string, int>
            {
                {"iframe",0},
            };

            dados_teste["Possivel Uso de Iframe sem SandBox"] = new string[3][];
            dados_teste["Possivel Uso de Iframe sem SandBox"][(int)NivelRisco.Alto] = new string[]
            {
                "string userInput = \"<iframe src=\\\"https://www.example.com\\\" onload='stealCookies()'></iframe>\";"
            };     
            dados_teste["Possivel Uso de Iframe sem SandBox"][(int)NivelRisco.Medio] = new string[]
            {
               "string userInput = \"<iframe src=\\\"https://www.example.com\\\" onload='alert(\\\"Você foi hackeado!\\\")></iframe>\";"
            };
            dados_teste["Possivel Uso de Iframe sem SandBox"][(int)NivelRisco.Baixo] = new string[]
            {
                "string userInput = \"<iframe src=\\\"https://www.example.com\\\"></iframe>\";"
            };*/    

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
                {"http://example.com",0},
                {"response.redirect(url);",0 }
                 // Adicione outras palavras reservadas conforme necessário
            };

            dados_teste["Possivel Redirecionamento de Domínio"] = new string[3][];
            dados_teste["Possivel Redirecionamento de Domínio"][(int)NivelRisco.Alto] = new string[]
            {
                "request.AllowAutoRedirect = true;"
            };
            dados_teste["Possivel Redirecionamento de Domínio"][(int)NivelRisco.Medio] = new string[]
            {
               "request.AllowAutoRedirect = false;"
            };
            dados_teste["Possivel Redirecionamento de Domínio"][(int)NivelRisco.Baixo] = new string[]
            {
               ""
            };*/
            
            //Chaves de Criptografia
            padroes["Possivel Fragilidade de Chave de Criptografia"] = new Dictionary<string, int>
            {
                { "aes",0 },
                { "rsa",0 },
                { "dsa",0 },
                { "byte[]",1 },
                {"string privkey",2 }
            };

            dados_teste["Possivel Fragilidade de Chave de Criptografia"] = new string[3][];
            dados_teste["Possivel Fragilidade de Chave de Criptografia"][(int)NivelRisco.Alto] = new string[]
            {
               "aes aes = aes.create()",
                null,
                "static string privateKey = \"ultrasecretprivatekey\";"
            };
            dados_teste["Possivel Fragilidade de Chave de Criptografia"][(int)NivelRisco.Medio] = new string[]
            {
                "dsa dsa = dsa.create()",
                "byte[] key = new byte[16];"
            };
            dados_teste["Possivel Fragilidade de Chave de Criptografia"][(int)NivelRisco.Baixo] = new string[]
            {
                "rsa rsa = rsa.create()",
                "byte[] key = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };",
            };

            //Privacy Violation
            /*padroes["Possivel Violação de Privacidade"] = new Dictionary<string, int>
            {
                { "breach",0 },
                {"leak",1},
                {"expose",2},
                {"hack",3},
                {"exploit",4},
                {"infiltrate",5},
                {"compromise",6},
                {"intrude",7},
                {"access",8},
                {"steal",9},
                {"phishing",10},
                {"identity theft",11},
            // Adicione outras palavras reservadas conforme necessário
            };
            dados_teste["Possivel Violação de Privacidade"][(int)NivelRisco.Alto] = new string[]
            {

            };
            dados_teste["Possivel Violação de Privacidade"][(int)NivelRisco.Medio] = new string[]
            {

            };
            dados_teste["Possivel Violação de Privacidade"][(int)NivelRisco.Baixo] = new string[]
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
                "string path =\"c:\\\\(?:\\.\\.|[^\\\\]+)*(?:\\\\|$)\";",
                "string path =\"d:\\\\(?:\\.\\.|[^\\\\]+)*(?:\\\\|$)\";",
                "string path =\"e:\\\\(?:\\.\\.|[^\\\\]+)*(?:\\\\|$)\";",
            };
            dados_teste["Possivel Caminho Transversal"][(int)NivelRisco.Medio] = new string[]
            {
                "string path =\"c:\\\\(?:[^\\\\]+\\\\)*[^\\\\]+\"",
                "string path =\"d:\\\\(?:[^\\\\]+\\\\)*[^\\\\]+\"",
                "string path =\"e:\\\\(?:[^\\\\]+\\\\)*[^\\\\]+\"",
            };
            dados_teste["Possivel Caminho Transversal"][(int)NivelRisco.Baixo] = new string[]
            {
                "string path =\"c:\\\\[^\\\\]+\"",
                "string path =\"d:\\\\[^\\\\]+\"",
                "string path =\"e:\\\\[^\\\\]+\"",
            };

            // HSTS Header
            padroes["Possivel HSTS Header"] = new Dictionary<string, int>
            {
                { "response.addheader",0 }
            };
            dados_teste["Possivel HSTS Header"] = new string[3][];
            dados_teste["Possivel HSTS Header"][(int)NivelRisco.Alto] = new string[]
            {
                null
            };
            dados_teste["Possivel HSTS Header"][(int)NivelRisco.Medio] = new string[]
            {
                "response.addheader(\"strict-transport-security\", \"max-age=3600\");"

            };
            dados_teste["Possivel HSTS Header"][(int)NivelRisco.Baixo] = new string[]
            {
                "response.addheader(\"strict-transport-security\", \"max-age=0\");",               
            };

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
            /*padroes["Possivel Heap Inspection"] = new Dictionary<string, int>
            {
                {"new",0 },
                {"weakreference",1},
                {"unsafe",2 },
                {"marshal",3 },
                {"pinning",4 }
            
            };

            dados_teste["Possivel Heap Inspection"] = new string[3][];
            dados_teste["Possivel Heap Inspection"][(int)NivelRisco.Alto] = new string[]
            {
                "var obj = new byte[1024*1024];",
                "public unsafe class classe",
                "intptr address = marshal.allochglobal(4096);"
            };          
            dados_teste["Possivel Heap Inspection"][(int)NivelRisco.Medio] = new string[]
            {
                "var obj = classe(var parA, var parB);",
                "static unsafe void main(string[] args)",
                "marshal.zerofreeglobalallocunicode(hwnd);"
            };
            dados_teste["Possivel Heap Inspection"][(int)NivelRisco.Baixo] = new string[]
            {
                "var obj = new object();",
                "",
                "intptr buffer = marshal.allochglobal(1024);"
            };*/
        }

        public List<(Vulnerabilidade Vulnerabilidade, List<int> Linhas)> VulnerabilidadesEncontradas
        {
            get { return vulnerabilidadesEncontradas; }
        }

        public int getPrecision()
        {
            try 
            {
                double valor = verdadeiros_positivos / VulnerabilidadesEncontradas.Count;

                if (falsos_positivos==0)
                {
                    return (int)Math.Round(valor, 0);
                }


                valor = (verdadeiros_positivos / verdadeiros_positivos + falsos_positivos) / VulnerabilidadesEncontradas.Count;

                return (int)Math.Round(valor,0);
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

        public async Task Visit(Dictionary<string,List<int>>Linhas) //Tempo de Compexidade: O(30n) <=> O(n)                                                                                                                               
        {
            Task[] tarefas = new Task[padroes.Count];
            int i = 0;

            foreach(var p in padroes.Keys)
            {
                tarefas[i] = Task.Run(() => AnalisarVulnerabilidade(Linhas, p, padroes[p])); 
                i++;
            }
        
            await Task.WhenAll(tarefas);
        
        }

        void AnalisarVulnerabilidade(Dictionary<string,List<int>> Linhas, string padrao,Dictionary<string,int> palavras)
        {
            int indicePadrao;

            List<int> linhasVulneraveis = new List<int>();
            

            foreach(var line in Linhas.Keys)
            {
                if(ContemUmaPalavra(line,palavras, out indicePadrao))
                {
                    string min = line.ToLower();

                    //Este array guarda a precisão dos dados de teste correspondentes à vulnerabilidade encontrada para diferentes niveis de risco
                    double[] precisao = {
                    CalculateSimilarity(min,dados_teste[padrao][(int)NivelRisco.Alto][indicePadrao])* 100,
                    CalculateSimilarity(min,dados_teste[padrao][(int)NivelRisco.Medio][indicePadrao])* 100,
                    CalculateSimilarity(min,dados_teste[padrao][(int)NivelRisco.Baixo][indicePadrao])*100
                    };

                    int index = Array.IndexOf(precisao, precisao.Max());
                    
                    string codigoCorrigido = line;//Esta variavel será o código html corrigido

                    if (Math.Round(precisao[index]) >= 50)
                    {
                        //Verifica se existe sinal de menor ou maio naquela linha para evitar a criação de tags no relatório HTML
                        if (line.IndexOf("<") != -1 || line.IndexOf(">") != -1)
                        {
                     
                            codigoCorrigido = SubstituirSimbolos(line);
                        }

                        var vul = new Vulnerabilidade(padrao, codigoCorrigido, (NivelRisco)index);
                        /*linhasVulneraveis.Concat(Linhas[line]);

                        foreach(int i in Linhas[line])
                        {
                            linhasVulneraveis.Add(i);
                        }*/

                        AdicionarVulnerabilidade(vul, Linhas[line]);
                        verdadeiros_positivos += precisao[index];
                    }

                    else falsos_positivos += precisao[index];
                }
            }

        }

        /*private void AnalisarVulnerabilidade(string code, List<int> Linhas ,Dictionary<string, int> palavras, string nomeVulnerabilidade)
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
                    if(code.IndexOf("<")!=-1 || code.IndexOf(">")!=-1)
                    {
                        code = SubstituirSimbolos(code);
                    }
                    
                    AdicionarVulnerabilidade(nomeVulnerabilidade, Linhas,code, (NivelRisco)index);
                    verdadeiros_positivos += precisao[index];
                }

                else falsos_positivos+= precisao[index];

            }
        }*/

        static bool isEndOfSubString(string s,char a,char b, char c)
        {
            return s +a+b +c == "\";";
        }

        private static string SubstituirSimbolos(string texto)
        {
            int index = texto.IndexOf("\"");

            if (index == -1)
            {
                return texto;
            }

            try
            {
                for (int i = index + 1; i < texto.Length - 1  || !isEndOfSubString("", texto[i], texto[i + 1], texto[i+2]); i++)
                {
                    if (texto[i] == '<')
                    {
                        texto = texto.Remove(i, 1).Insert(i, "&lt;");
                        
                        i += 3;
                    }
                    else if (texto[i] == '>')
                    {
                        texto = texto.Remove(i, 1).Insert(i, "&gt;");
                        i += 3;
                    }
                }
            }
            catch (IndexOutOfRangeException)
            {
                return texto;
            }

            return texto;
        }


        private void AdicionarVulnerabilidade(Vulnerabilidade vulnerabilidade, List<int> linhas)
        {
            vulnerabilidadesEncontradas.Add((vulnerabilidade,linhas));
        }
        

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
        //Justifica o porquê deste algoritmo
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
