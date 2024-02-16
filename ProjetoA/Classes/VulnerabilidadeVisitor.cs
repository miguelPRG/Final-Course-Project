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

    public class VulnerabilidadeVisitor : CSharpSyntaxWalker
    {
        //Lista de vulnerabilidades encontradas
        private List<(string Tipo, int Linha, string Codigo, NivelRisco NivelRisco)> vulnerabilidadesEncontradas;

        //Diciónário utilizado para testar as vulnerabilidades encontradas
        Dictionary<string, Regex[][]> dados_teste;

        //Lista que guarda palavras reservadas para cada tipo de vulnerabilidade
        Dictionary<string, Dictionary<string, int>> padroes;

        int falsos_positivos = 0;
        int verdadeiros_positivos = 0;

        public VulnerabilidadeVisitor()
        {
            vulnerabilidadesEncontradas = new List<(string, int, string, NivelRisco)>();
            dados_teste = new Dictionary<string, Regex[][]>();
            padroes = new Dictionary<string, Dictionary<string, int>>();

            //SQL
            padroes["Possível Injeção de SQL"] = new Dictionary<string, int>
            {
                { "select",0},
                { "insert",1},
                { "update",2},
                { "delete",3},
                { "create",4},
                { "alter",5},
                { "drop",6},
            };

            dados_teste["Possível Injeção de SQL"] = new Regex[3][];
            dados_teste["Possível Injeção de SQL"][(int)NivelRisco.Alto] = new Regex[]
            {
               new Regex(@"select\s+\*\s+from\s+tabela\s+where\s+coluna\s+=\s+'\{userinput\}'", RegexOptions.IgnoreCase| RegexOptions.Singleline),
               new Regex(@"insert\s+into\s+users\s+\(username\)\s+values\s+\('\s*\+\s+userinput\s+\+\s+'\)", RegexOptions.IgnoreCase| RegexOptions.Singleline),
               new Regex(@"update\s+users\s+set\s+password\s+=\s+'newpassword'\s+where\s+userid\s+=\s+\+\s+userinput", RegexOptions.IgnoreCase| RegexOptions.Singleline),
               new Regex(@"delete\s+from\s+tabela\s+where\s+id\s+=\s+\+\s+userInput", RegexOptions.IgnoreCase| RegexOptions.Singleline),
               new Regex(@"create\s+table\s+\+\s+userinput\s+\(id\s+int,\s+name\s+varchar\(255\),\s+email\s+varchar\(255\)\)", RegexOptions.IgnoreCase| RegexOptions.Singleline),
               new Regex(@"alter\s+table\s+\{userinput\}\s+drop\s+column\s+\{columname\}", RegexOptions.IgnoreCase| RegexOptions.Singleline),
               new Regex(@"drop\s+table\s+users;\s+select\s+\*\s+from\s+sensitive_information", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            };
            dados_teste["Possível Injeção de SQL"][(int)NivelRisco.Medio] = new Regex[]
            {
                new Regex(@"select\s+\*\s+from\s+tabela\s+where\s+coluna\s+=\s+'\s*\+\s+inputmediumrisk\s+\+\s*", RegexOptions.IgnoreCase| RegexOptions.Singleline),
                new Regex(@"insert\s+into\s+users\s+\(username,\s+password\)\s+values\s+\('\s*\+\s+username\s+\+\s+'", RegexOptions.IgnoreCase| RegexOptions.Singleline),
                new Regex(@"update\s+users\s+set\s+password\s+=\s+'newpassword'\s+where\s+username\s+=\s+'\s*\+\s+username\s+\+\s*", RegexOptions.IgnoreCase| RegexOptions.Singleline),
                new Regex(@"delete\s+from\s+tabela\s+where\s+id\s+=\s+\+\s+userinput\s+\;", RegexOptions.IgnoreCase| RegexOptions.Singleline),
                new Regex(@"create\s+table\s+\+\s+tablename\s+\(id\s+int,\s+name\s+varchar\(255\),\s+email\s+varchar\(255\)\)", RegexOptions.IgnoreCase| RegexOptions.Singleline),
                new Regex(@"alter\s+table\s+\+\s+tablename\s+\+column\s+\+\s+columnname\s+varchar\(100\)", RegexOptions.IgnoreCase| RegexOptions.Singleline),
                new Regex(@"drop\s+table\s+users;\s+\-\-", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            };
            dados_teste["Possível Injeção de SQL"][(int)NivelRisco.Baixo] = new Regex[]
            {
                new Regex(@"select\s+\*\s+from\s+tabela", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"insert\s+into\s+users\s+\(username,\s+password\)\s+values\s+\('johndoe',\s+'password123'\)", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"update\s+table\s+set\s+column\s+=\s+@value\s+where\s+id\s+=\s+@id", RegexOptions.IgnoreCase| RegexOptions.Singleline),
                new Regex(@"delete\s+from\s+tabela\s+where\s+id\s+=\s+1;", RegexOptions.IgnoreCase| RegexOptions.Singleline),
                new Regex(@"create\s+table\s+users\s+\(id\s+int,\s+name\s+varchar\(255\),\s+email\s+varchar\(255\)\)", RegexOptions.IgnoreCase| RegexOptions.Singleline),
                new Regex(@"alter\s+table\s+user\s+add\s+column\s+age\s+int",  RegexOptions.IgnoreCase| RegexOptions.Singleline),
                new Regex(@"drop\s+table\s+users", RegexOptions.IgnoreCase | RegexOptions.Singleline)
            };

            //Client XSS
            padroes["Possível Cliente XSS"] = new Dictionary<string, int>
            {
                { "<script>",0 },
                { "<img>", 1 },
                { "<iframe>", 2 },
                { "<object>", 3 },
                // Adicione outras palavras reservadas conforme necessário
            };

            dados_teste["Possível Cliente XSS"] = new Regex[3][];
            dados_teste["Possível Cliente XSS"][(int)NivelRisco.Alto] = new Regex[]
        {
            // Alto risco: entrada de usuário inserida diretamente em contexto perigoso
            new Regex(@"<\s*script.*?>.*?<\s*/\s*script\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            new Regex(@"<img[^>]+?(?:(?:\s+on\w+\s*=\s*(?:\""[^\""]*?\""|'[^']*?'|[^>]+?))|(?:(?:\s*src\s*=)|(?:\s*data-[\w-]+\s*=)|(?:\s*action\s*=))).*?>", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            new Regex(@"\<iframe\>", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            new Regex(@"/<object\s+.*\s+data=[\""\'].*[\""\'].*>\s*<\/object>/", RegexOptions.IgnoreCase | RegexOptions.Singleline),
        };
            dados_teste["Possível Cliente XSS"][(int)NivelRisco.Medio] = new Regex[]
        {
            // Médio risco: entrada de usuário com filtragem inadequada
            new Regex(@"<\s*script[^>]*>(.*?)<\s*/\s*script\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            new Regex(@"<img.*?(?:src=|on\w+\s*=|style\s*=|action=|data-[\w-]+\s*=).*?>", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            new Regex(@"\<!--.*\<iframe\>.*--\>|\b\<iframe\s*\>|\b\<iframe\>\s*.*\b", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            new Regex(@"/<object[^>]*>.*<\/object>/", RegexOptions.IgnoreCase | RegexOptions.Singleline),
        };
            dados_teste["Possível Cliente XSS"][(int)NivelRisco.Baixo] = new Regex[]
        {
            // Baixo risco: entrada direta de usuário no código
            new Regex(@"\b(?:<\s*script\s*>)\b", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            new Regex(@"\b(?:<\s*img\s*>)\b",RegexOptions.IgnoreCase | RegexOptions.Singleline),
            new Regex(@"/<iframe[^>]*>.*<\/iframe>/", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            new Regex("/<object[^>]*>.*<\\/object>/", RegexOptions.IgnoreCase | RegexOptions.Singleline),
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
            // Adicione outras palavras reservadas conforme necessário
            };

            dados_teste["Possível Target Blank"] = new Regex[3][];
            dados_teste["Possível Target Blank"][(int)NivelRisco.Alto] = new Regex[]
            {
                new Regex("<a\\s+(?=\\s)(?=(?:[^>\"']|\"[^\"]*\"|'[^']*')*?\\s(?:target\\s*=\\s*[\"']_blank[\"']))(?:[^>\"']|\"[^\"]*\"|'[^']*')*?\\s(?:rel\\s*=\\s*[\"'](?:noopener|noreferrer)[\"'])?(?:[^>\"']|\"[^\"]*\"|'[^']*')*?\\s(?:href\\s*=\\s*[\"'](?!javascript:|data:)[^\"']*[\"'])(?:[^>\"']|\"[^\"]*\"|'[^']*')*?>", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            };
            dados_teste["Possível Target Blank"][(int)NivelRisco.Medio] = new Regex[]
            {
                new Regex(@"target\s*=\s*[""']_blank[""'](?!.*\brel\s*=\s*[""'](?:noopener|noreferrer)[""'])", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            };
            dados_teste["Possível Target Blank"][(int)NivelRisco.Baixo] = new Regex[]
            {
                new Regex(@"target\s*=\s*[""']_blank[""']", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            };

            //Cookies
            padroes["Possiveis Cookies não Protegidos"] = new Dictionary<string, int>
        {
            { "expires",0 },
            { "max-age",1 },
            { "domain",2 },
            { "path",3 },
            { "set-cookie",4 },
            { "httpcookie",5 },
            { "httpcontext",6 },

            // Adicione outras palavras reservadas conforme necessário
        };

            dados_teste["Possiveis Cookies não Protegidos"] = new Regex[3][];
            dados_teste["Possiveis Cookies não Protegidos"][(int)NivelRisco.Alto] = new Regex[]
            {
                new Regex("\\bexpires\\s*=\\s*(?:\\'[^\\']*\\'|\\\"[^\\\"]*\\\"|\\d+)", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex("\\bmax-age\\s*=\\s*\\d+\\s*;\\s*httponly\\b", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"(?i)\bhttp[s]?\b.*\b(domain)\b", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"\bcookies?\b\s*(?=.*\bpath\b).*;(?:(?!\bsecure\b).)*$", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"Set-Cookie: (?!.*;\s*Secure).*$", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"\bnew\s+HttpCookie\s*\(.+\)\s*\{\s*HttpOnly\s*=\s*false\s*(,\s*Secure\s*=\s*false)?", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"\bHttpContext\s*\.\s*Current\s*\.\s*Request\s*\.\s*Cookies\s*\.\s*", RegexOptions.IgnoreCase | RegexOptions.Singleline)
            };
            dados_teste["Possiveis Cookies não Protegidos"][(int)NivelRisco.Medio] = new Regex[]
            {
                new Regex("\\bexpires\\s*=\\s*(?:\\'[^\\']*\\'|\\\"[^\\\"]*\\\")", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex("\\bmax-age\\s*=\\s*\\d+\\s*;\\s*secure\\b", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"(?i)\bcookie\s*=\s*[^;]*(domain)[^;]*", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex("\\bcookies?\\b\\s*(?=.*\\bpath\\b).*(?!;secure).*$", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"Set-Cookie: (?=.*;\s*Secure)(?!.*;\s*HttpOnly).*$", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"\bnew\s+HttpCookie\s*\(", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"\bHttpContext\s*\.\s*Current\s*\.\s*Response\s*\.\s*Cookies\s*\.\s*", RegexOptions.IgnoreCase | RegexOptions.Singleline)
            };
            dados_teste["Possiveis Cookies não Protegidos"][(int)NivelRisco.Baixo] = new Regex[]
            {
                new Regex("\\bexpires\\s*=\\s*", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex("\\bmax-age\\s*=\\s*\\d+\\b", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"(?i)\bdomain\b", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"\bcookies?\b\s*(?:(?!\bpath\b).)*$", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"Set-Cookie: (?!.*;\\s*Secure)(?!.*;\\s*HttpOnly).*$", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"\bhttpcookie\b", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"\bHttpContext\s*\[\s*[""']Response[""']\s*\]\s*\.\s*Cookies\s*\[\s*", RegexOptions.IgnoreCase | RegexOptions.Singleline)
            };

            //CSP Header
            padroes["Possivel CSP Header"] = new Dictionary<string, int>
        {
            {"script-src",0 },
            {"base-uri",1},
            {"form-action",2},
            {"frame-ancestors",3},
            {"plugin-types",4},
            //{"report-uri",5},
            {"upgrade-insecure-requests",5},
            {"block-all-mixed-content",6},
            // Adicione outras palavras reservadas conforme necessário
        };

            dados_teste["Possivel CSP Header"] = new Regex[3][];
            dados_teste["Possivel CSP Header"][(int)NivelRisco.Alto] = new Regex[]
            {
                new Regex(@"Content-Security-Policy:\s*script-src\s*'none'\s*;", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"base-uri\s*:\s*[""'][^""'\s;]+['""]\s*\+", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"form-action:\s*['""]?(?!'self')(?!https?:\/\/example\.com)['""]?.*", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"(frame-ancestors\s*:\s*)http://|https://|'unsafe-inline'", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"\bplugin-types\s*=\s*""[^""]*(javascript:|data:|blob:)[^""]*""", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                //new Regex(@"Content-Security-Policy:\s*(?:.|[])*\breport-uri\s*:", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"Content-Security-Policy\s*:\s*(?:[^;""'`\\]|\\.)*\s*upgrade-insecure-requests\s*(?:[^;""'`\\]|\\.)*", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"(?i)(Response\s*\.Write\(.*block-all-mixed-content.*\))", RegexOptions.IgnoreCase | RegexOptions.Singleline)
            };
            dados_teste["Possivel CSP Header"][(int)NivelRisco.Medio] = new Regex[]
            {
                new Regex(@"Content-Security-Policy:\s*script-src\s*'self'\s*'unsafe-inline'\s*;", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"base-uri\s*:\s*[^""'\s;]+", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"form-action:\s*['""]?https?:\/\/[^'""]+['""]?", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"frame-ancestors\s*:\s*'self'\s*https://subdominio\.exemplo\.com", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"\bplugin-types\s*=\s*""[^""]*""", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                //new Regex(@"^Content-Security-Policy:\s*(?:.|[])*report-uri\s*$", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"Content-Security-Policy\s*:\s*[^;]*\s*upgrade-insecure-requests[^;]*", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"(?i)(Response\s*\.Headers\s*\[""Content-Security-Policy""\]\s*=\s*\"".*block-all-mixed-content.*\""\s*;)", RegexOptions.IgnoreCase | RegexOptions.Singleline)
            };
            dados_teste["Possivel CSP Header"][(int)NivelRisco.Baixo] = new Regex[]
            {
                new Regex(@"Content-Security-Policy:\s*script-src\s*'self'\s*;", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"base-uri\s*=\s*[""']?\s*[^""'\s;]+", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"form-action:\s*'self'", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"(?i)frame-ancestors\s*:\s*'[^']*'", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"\bplugin-types\b", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                //new Regex(@"^Content-Security-Policy:\s*report-uri\s*$", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"Content-Security-Policy\s*:\s*upgrade-insecure-requests", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@".*CSP.*block-all-mixed-content.*", RegexOptions.IgnoreCase | RegexOptions.Singleline)
            };

            // Iframe 
            padroes["Possivel Uso de Iframe sem SandBox"] = new Dictionary<string, int>
         {
            {"iframe",0},
            {"sandbox",0}
             // Adicione outras palavras reservadas conforme necessário
         };

            dados_teste["Possivel Uso de Iframe sem SandBox"] = new Regex[3][];
            dados_teste["Possivel Uso de Iframe sem SandBox"][(int)NivelRisco.Alto] = new Regex[]
            {
                new Regex(@"\<iframe(?![^>]*\ssandbox\s)(?![^>]*\sallow-scripts\s)(?![^>]*\sallow-same-origin\s)(\s+.*?)*\>(.|\s)*?\<\/iframe\>", RegexOptions.IgnoreCase | RegexOptions.Singleline), 
            };
            dados_teste["Possivel Uso de Iframe sem SandBox"][(int)NivelRisco.Medio] = new Regex[]
            {
                new Regex(@"\<iframe(?![^>]*\ssandbox\s)(\s+.*?)*\>(.|\s)*?\<\/iframe\>", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            };
            dados_teste["Possivel Uso de Iframe sem SandBox"][(int)NivelRisco.Baixo] = new Regex[]
            {
                new Regex(@"\<iframe(\s+.*?)*\>(.|\s)*?\<\/iframe\>", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            };

            // JQuery
            padroes["Possivel JQuery"] = new Dictionary<string, int>
            {
                {"document",0},
                {"function",1},
                {"ajax",2},
                {"post",3},
                 // Adicione outras palavras reservadas conforme necessário
             };

            dados_teste["Possivel JQuery"] = new Regex[3][];
            dados_teste["Possivel JQuery"][(int)NivelRisco.Alto] = new Regex[]
            {
                new Regex(@"\bdocument\s*\.\s*(write|writeln|innerHTML|outerHTML|eval)\s*\(", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"\$\(.+\)\.(click|change|mouseover|keydown)\(", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"(\.ajax\(|\.get\(|\.post\(|\.getJSON\()\s*\([^']*['""].*['""]\s*\+\s*[^']*['""].*['""]\s*\+\s*[^']*['""].*['""]\)", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"\.post\s*\(\s*['""][^'""]*['""]\s*,\s*{\s*['""][^'""]*['""]\s*:\s*['""][^'""]*['""]\s*}\s*\)", RegexOptions.IgnoreCase | RegexOptions.Singleline)
            };
            dados_teste["Possivel JQuery"][(int)NivelRisco.Medio] = new Regex[]
            {
                new Regex(@"\bdocument\s*\.\s*\w+\s*\(", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"\$\(.+\)\.(append|prepend|before|after)\(", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"(\.ajax\(|\.get\(|\.post\(|\.getJSON\()\s*\([^']*'[^']*'\s*,\s*[^']*'[^']*'\s*,\s*[^']*'[^']*'\)", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"\.post\s*\(\s*['""][^'""]*['""]\s*,\s*['""][^'""]*['""]\s*\)", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            };
            dados_teste["Possivel JQuery"][(int)NivelRisco.Baixo] = new Regex[]
            {
                new Regex(@"\bdocument\b", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"\$\(\s*'[^']*'\s*\)\.function\(", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"(\.ajax\(|\.get\(|\.post\(|\.getJSON\()", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"\.post\s*\(", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            };

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
            padroes["Possivel Redirecionamento de Domínio"] = new Dictionary<string, int>
            {
                {"window.location",0},
                {"document.location",1},
                {"document.url",2},
                {"location.href",3},
                //{"location.replace",},
                //{"location.assign",4},
                 // Adicione outras palavras reservadas conforme necessário
            };

            dados_teste["Possivel Redirecionamento de Domínio"] = new Regex[3][];
            dados_teste["Possivel Redirecionamento de Domínio"][(int)NivelRisco.Alto] = new Regex[]
            {
                new Regex(@"window\.location\s*=\s*['""][^'""]+['""];", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"document\.location\s*=\s*(Request\.UrlReferrer|Request\.Url|Request\.UserAgent|Request\.ServerVariables\[""HTTP_REFERER""\]|Request\.ServerVariables\[""HTTP_HOST""\]|Request\.ServerVariables\[""HTTP_USER_AGENT""\]|[^;]+);"
                , RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"(document\.url\s*\(\s*[""']\s*(http|https):\/\/)", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"\blocation\.href\s*=\s*Request\.QueryString\b",RegexOptions.IgnoreCase | RegexOptions.Singleline),
                //new Regex(@"(if|while|for)\s*\([^)]*\)\s*\{(?:[^{}]|(?R))*\blocation\.replace\s*\(", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                //new Regex(@"\blocation\.assign\s*\(\s*[""'][^""']*?(?:(?:https?:\/\/)?(?:www\.)?(?:[^\/]+\.)+(?:com|org|net|gov|mil|biz|info|io|edu|tv|co|uk|ca|de|fr|au|jp|ru|nl|es|it|se|no|ch|dk)\b", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            };
            dados_teste["Possivel Redirecionamento de Domínio"][(int)NivelRisco.Medio] = new Regex[]
            {
                new Regex(@"window\.location\s*=\s*\([^)]*\)\s*;", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"document\.location\s*=\s*(Request\[""[^""]+""\]|Request\.Query[String|Url]|Request\.Params\[""[^""]+""\]|Server\.UrlDecode\(""[^""]+""\)|Server\.HtmlDecode\(""[^""]+""\)|[^;]+);", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"(document\.url\s*\(\s*[""'])", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"\blocation\.href\s*=\s*"".*""\s*;", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                //new Regex(@"function\s+\w+\s*\(\s*\)\s*\{(?:[^{}]|(?R))*\blocation\.replace\s*\(", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                //new Regex(@"\blocation\.assign\s*\(\s*[""'][^""']*?\.com\b", RegexOptions.IgnoreCase | RegexOptions.Singleline)
            };
            dados_teste["Possivel Redirecionamento de Domínio"][(int)NivelRisco.Baixo] = new Regex[]
            {
                new Regex(@"window\.location\s*=\s*(document|window)\.location;", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"document\.location\s*=\s*(""[^""]+""|'[^']+'|[^;]+);", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"document\.url", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"\blocation\.href\b", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                //new Regex(@"\blocation\.replace\s*\(", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                //new Regex(@"\blocation\.assign\s*\(\s*[""'](?:https?:\/\/)?(?:www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            };

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

            dados_teste["Possivel Caminho Transversal"] = new Regex[3][];
            dados_teste["Possivel Caminho Transversal"][(int)NivelRisco.Alto] = new Regex[]
            {
                new Regex("c:\\\\(?:\\.\\.|[^\\\\]+)*(?:\\\\|$)", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex("d:\\\\(?:\\.\\.|[^\\\\]+)*(?:\\\\|$)", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex("e:\\\\(?:\\.\\.|[^\\\\]+)*(?:\\\\|$)", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            };
            dados_teste["Possivel Caminho Transversal"][(int)NivelRisco.Medio] = new Regex[]
            {
                new Regex("c:\\\\(?:[^\\\\]+\\\\)*[^\\\\]+", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex("d:\\\\(?:[^\\\\]+\\\\)*[^\\\\]+", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex("e:\\\\(?:[^\\\\]+\\\\)*[^\\\\]+", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            };
            dados_teste["Possivel Caminho Transversal"][(int)NivelRisco.Baixo] = new Regex[]
            {
                new Regex("c:\\\\[^\\\\]+", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex("d:\\\\[^\\\\]+", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex("e:\\\\[^\\\\]+", RegexOptions.IgnoreCase | RegexOptions.Singleline),
            };

            // HSTS Header
            padroes["Possivel HSTS Header"] = new Dictionary<string, int>
            {
                { "strict-transport-security",0},
                { "max-age",1},
                { "preload",2},
                 // Adicione outras palavras reservadas conforme necessário
            };

            dados_teste["Possivel HSTS Header"] = new Regex[3][];
            dados_teste["Possivel HSTS Header"][(int)NivelRisco.Alto] = new Regex[]
            {
                new Regex("(?i)Response\\.Headers\\.Add\\((\"|')strict-transport-security(\"|')\\s*,\\s*(\"|')(max-age\\s*=\\s*\\d{1,3}(|s)\\s*(,|$))*(?!\\s*preload)\\s*(\"|')\\);", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"max-age\s*=\s*\d{1,5}\s*;\s*includeSubDomains", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex("\\bHSTS\\b\\s*\\(\\s*\".*preload.*\"\\s*\\)", RegexOptions.IgnoreCase | RegexOptions.Singleline)
            };
            dados_teste["Possivel HSTS Header"][(int)NivelRisco.Medio] = new Regex[]
            {
                new Regex("(?i)Response\\.Headers\\.Add\\((\"|')strict-transport-security(\"|')\\s*,\\s*(\"|')max-age=.*(\"|')(?!\\s*,\\s*\"includeSubDomains)(\"|')\\);", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"max-age\s*=\s*\d{1,5}", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex("\\bHSTS\\b\\s*=\\s*\".*preload.*\"", RegexOptions.IgnoreCase | RegexOptions.Singleline)
            };
            dados_teste["Possivel HSTS Header"][(int)NivelRisco.Baixo] = new Regex[]
            {
                new Regex("(?i)Response\\.Headers\\.Add\\((\"|')strict-transport-security(\"|')\\s*,\\s*(\"|')max-age=.*(\"|')\\);", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex(@"max-age\s*=\s*\d", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                new Regex("\\bHSTS\\b.*preload\\b", RegexOptions.IgnoreCase | RegexOptions.Singleline)
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



        public override void VisitLiteralExpression(LiteralExpressionSyntax node) /*Tempo de Compexidade: O(30n) <=> O(n) 
                                                                                   *onde n é o número de nós e 30= 10 *3 
                                                                                    */
        {
            string code_part = node.ToString();

            // Dictionary<string,Dictionary<string, int>>padroes
            // Dictionary<string, string[]> dados_teste;
            foreach (var nome in padroes.Keys)
            {
                AnalisarVulnerabilidade(code_part, node, padroes[nome], nome);
            }


            base.VisitLiteralExpression(node);
        }


        private void AnalisarVulnerabilidade(string code, LiteralExpressionSyntax node, Dictionary<string, int> palavras, string nomeVulnerabilidade)
        {
            if (ContemUmaPalavra(code, palavras, out int value))
            {
                //Este array guarda a precisão dos dados de teste correspondentes à vulnerabilidade encontrada para diferentes niveis de risco
                double[] precisao = {
                    CompareWithRegex(code,dados_teste[nomeVulnerabilidade][(int)NivelRisco.Alto][value]),
                    CompareWithRegex(code,dados_teste[nomeVulnerabilidade][(int)NivelRisco.Medio][value]),
                    CompareWithRegex(code,dados_teste[nomeVulnerabilidade][(int)NivelRisco.Baixo][value])
                };

                //Qual o nivel de risco mais provavel da vulnerabilidade encontrada
                int index = Array.IndexOf(precisao, precisao.Max());

                if (Math.Round(precisao[index]) >= 50)
                {
                    AdicionarVulnerabilidade(nomeVulnerabilidade, node, (NivelRisco)index);
                    verdadeiros_positivos++;
                }

                else falsos_positivos++;

            }
        }

        private void AdicionarVulnerabilidade(string nomeVulnerabilidade, LiteralExpressionSyntax node, NivelRisco nivelRisco)
        {
            vulnerabilidadesEncontradas.Add((nomeVulnerabilidade, node.GetLocation().GetLineSpan().StartLinePosition.Line, node.ToString(), nivelRisco));
        }
        //PREFERENCIALMENTE. Tenta utilizar estes métodos para determinar precisão:

        static double CompareWithRegex(string consultaSql, Regex expressaoRegular)
        {
            int distancia = LevenshteinDistance(consultaSql.ToLower(), expressaoRegular.ToString().ToLower());
            int maiorComprimento = Math.Max(consultaSql.Length, expressaoRegular.ToString().Length);
            double taxaPrecisao = (1 - (double)distancia / maiorComprimento) * 100;
            return taxaPrecisao;
        }

        static int LevenshteinDistance(string s, string t)
        {
            int n = s.Length;
            int m = t.Length;
            int[,] d = new int[n + 1, m + 1];

            if (n == 0)
                return m;
            if (m == 0)
                return n;

            for (int i = 0; i <= n; d[i, 0] = i++) ;
            for (int j = 0; j <= m; d[0, j] = j++) ;

            for (int i = 1; i <= n; i++)
            {
                for (int j = 1; j <= m; j++)
                {
                    int cost = (t[j - 1] == s[i - 1]) ? 0 : 1;

                    d[i, j] = Math.Min(
                        Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1),
                        d[i - 1, j - 1] + cost);
                }
            }
            return d[n, m];
        }

        /*public static double Similarity(string s, string t)
        {
            int maxLength = Math.Max(s.Length, t.Length);
            if (maxLength == 0)
                return 1.0; // As duas strings estão vazias, então são idênticas
            int distance = LevenshteinDistance(s, t);
            return 1.0 - (double)distance / maxLength;
        }*/

        /*
        
        static double CalculateSimilarity(string query1, string query2)
        {
            int maxLength = Math.Max(query1.Length, query2.Length);
            if (maxLength == 0)
                return 100.0;

            int distance = LevenshteinDistance(query1, query2);
            return ((double)(maxLength - distance) / maxLength) * 100;
        }
        static int LevenshteinDistance(string s, string t)
        {
            int[,] d = new int[s.Length + 1, t.Length + 1];

            for (int i = 0; i <= s.Length; i++)
                d[i, 0] = i;

            for (int j = 0; j <= t.Length; j++)
                d[0, j] = j;

            for (int j = 1; j <= t.Length; j++)
            {
                for (int i = 1; i <= s.Length; i++)
                {
                    int cost = (s[i - 1] == t[j - 1]) ? 0 : 1;
                    d[i, j] = Math.Min(
                        Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1),
                        d[i - 1, j - 1] + cost);
                }
            }

            return d[s.Length, t.Length];
        }*/
    }
}

/*Analisar o tempo total de execução de scan do código inserido
 
 */