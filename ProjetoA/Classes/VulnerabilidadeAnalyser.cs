using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Windows.UI.Xaml.Shapes;

public class Vulnerability
{
    public string Tipo { get; set; }
    public string Codigo { get; set; }
    public NivelRisco Risco { get; set; }
    public List<int> Linhas { get; set; }

    public Vulnerability(string type, string node, NivelRisco riskLevel, List<int> lineNumbers)
    {
        Tipo = type;
        Codigo = node;
        Risco = riskLevel;
        Linhas = lineNumbers;
    }
}

public enum NivelRisco
{
    Alto,
    Medio,
    Baixo
}
public static class VulnerabilidadeAnalyzer
{
    static List<Vulnerability> vulnerabilities;

    public static List<Vulnerability> AnalisarVulnerabilidades(SyntaxNode root)
    {
        vulnerabilities = new List<Vulnerability>();

        // Analisar vulnerabilidades de XSS
        AnalyzeForInsecureDeserialization(root);

        // Analisar vulnerabilidades de SQL Injection
        //var sqlVulnerabilities = AnalyzeSQLInjection(root);
        //vulnerabilities.AddRange(sqlVulnerabilities);

        return vulnerabilities;
    }

    private static VariableDeclarationSyntax FindVariableDeclaration(IdentifierNameSyntax identifierName, SyntaxNode root)
    {
        var variableDeclarations = root.DescendantNodes()
            .OfType<VariableDeclarationSyntax>();

        foreach (var variableDeclaration in variableDeclarations)
        {
            foreach (var variable in variableDeclaration.Variables)
            {
                if (variable.Identifier.Text == identifierName.Identifier.Text)
                {
                    return variableDeclaration;
                }
            }
        }

        return null;
    }
   
    static void AdicionarVulnerabilidade(string tipo, string codigo, NivelRisco risco, int linha)
    {
        object obj = new object();

        var existingVulnerability = vulnerabilities
                       .FirstOrDefault(v => v.Codigo == codigo && v.Tipo == tipo);

        lock (obj)
        {
            if (existingVulnerability != null)
            {
                // Adicionar a nova linha à lista de linhas da vulnerabilidade existente
                existingVulnerability.Linhas.Add(linha);
                existingVulnerability.Linhas = existingVulnerability.Linhas.Distinct().ToList();
            }
            else
            {
                // Adicionar nova vulnerabilidade
                var lineNumbers = new List<int> { linha };
                vulnerabilities.Add(new Vulnerability(tipo, codigo, risco, lineNumbers));
            }
        }
    }

    static void AnalyzeSQLInjection(SyntaxNode root)
    {
        var declarations = root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>();
        var tipo = "SQL Injection";
        var risco = NivelRisco.Alto;

        foreach (var obj in declarations)
        {
            // Verificar se é uma declaração de SqlCommand
            if (obj.Type.ToString() == "SqlCommand")
            {
                // Iterar pelos argumentos do SqlCommand
                foreach (var arg in obj.ArgumentList.Arguments)
                {
                    // Verificar se o argumento é uma concatenação de strings
                    if (arg.Expression is BinaryExpressionSyntax binaryExpression &&
                        binaryExpression.OperatorToken.IsKind(SyntaxKind.PlusToken))
                    {
                        // Adicionar a vulnerabilidade
                       
                        var codigo = obj.ToString().Substring(0, 20);
                         // Ajuste conforme necessário
                        var linha = arg.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                        AdicionarVulnerabilidade(tipo, codigo, risco, linha);
                    }
                    // Verificar se o argumento é um identificador de variável que contenha uma string concatenada
                    else if (arg.Expression is IdentifierNameSyntax identifier)
                    {
                        var variable = root.DescendantNodes()
                                           .OfType<VariableDeclarationSyntax>()
                                           .FirstOrDefault(v => v.Variables.Any(var => var.Identifier.Text == identifier.Identifier.Text));

                        if (variable != null && variable.Variables.Any(v => v.Initializer.Value is BinaryExpressionSyntax))
                        {
                            var codigo = arg.ToString();
                            int index = codigo.IndexOfAny(new char[] { '\n', '\r' });
                            codigo = codigo.Substring(0, index);

                            var linha = arg.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                            AdicionarVulnerabilidade(tipo,codigo, risco, linha);
                        }
                    }
                }
            }
        }
    }
    static void AnalyzeForXSS(SyntaxNode root)
    {
        var tipo = "XSS";
        var risco = NivelRisco.Alto; // Ajuste conforme necessário

        var declarations = root.DescendantNodes().OfType<LocalDeclarationStatementSyntax>();

        foreach (var invocation in declarations)
        {
            // Verificar se o método invocado é Request.QueryString
            if (invocation.ToString().Contains("Request.QueryString"))
            {
                // Verificar se há uma invocação de Server.HtmlEncode com o valor de Request.QueryString
                var htmlEncodeInvocations = invocation.Ancestors().OfType<InvocationExpressionSyntax>()
                    .Where(inv => inv.ToString().Contains("Server.HtmlEncode"));

                if (!htmlEncodeInvocations.Any())
                {
                    // Se não houver Server.HtmlEncode para o valor de Request.QueryString, adicionar vulnerabilidade
                   
                    var codigo = invocation.ToString();
                    int index = codigo.IndexOfAny(new char[] { '\n', '\r' });
                    codigo = codigo.Substring(0, index);

                    var linha = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

                    AdicionarVulnerabilidade(tipo, codigo, risco, linha);
                }
            }
        }
    }
    static void AnalyzeForCSRF(SyntaxNode root)
    {
        var tipo = "CSRF";
        var risco = NivelRisco.Alto;

        var methods = root.DescendantNodes().OfType<MethodDeclarationSyntax>();

        foreach(var m in methods)
        {
            var listaAtributos = m.AttributeLists;

            int httpPost = 0;
            int antiForgery = 0;

            foreach (var a in listaAtributos)
            {
                if(a.ToString() == "[HttpPost]")
                {
                    httpPost++;
                }

                else if(a.ToString() == "[ValidateAntiForgeryToken]")
                {
                    antiForgery++;
                }
            }

            if(httpPost > antiForgery)
            {
                var codigo = m.ToString();
                int index = codigo.IndexOfAny(new char[] { '\n', '\r' });
                codigo = codigo.Substring(0, index);

                var linha = m.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

                AdicionarVulnerabilidade(tipo, codigo, risco, linha);
            }
        }


    }
    static void AnalyzeForInsecureDeserialization(SyntaxNode root)
    {
        var tipo = "Deserialização Insegura";
        var risco = NivelRisco.Alto;

        var blocos = root.DescendantNodes().OfType<BlockSyntax>();
       

        foreach(var b in blocos)
        {
            var variaveis = b.DescendantNodes().OfType<VariableDeclaratorSyntax>()
                              .Where(v => v.Initializer != null &&
                                    v.Initializer.Value.ToString().Contains("BinaryFormatter"));

            IEnumerable<InvocationExpressionSyntax> metodos = null;

            if (variaveis != null)
            {
                foreach(var v in variaveis)
                {
                    metodos = b.DescendantNodes().OfType<InvocationExpressionSyntax>()
                           .Where(m => m.Expression.ToString().Contains(v.Identifier + ".Deserialize"));

                    if (metodos != null)
                    {
                        foreach(var m in metodos)
                        {
                            var linha = m.Parent.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

                            AdicionarVulnerabilidade(tipo, m.Parent.ToString(), risco, linha);
                        }
                    }
                }
            }

            else continue;
            
        }

    }

    static void AnalyzeForInsecureRedirects(SyntaxNode root) { }
    static void AnalyzForNoSQLInjection(SyntaxNode root) { }
    static void AnalyzeForInsecureEncryption(SyntaxNode root) { }
    static void AnalyzeForLDAPInjection(SyntaxNode root) { }



    static bool IsUserInput(InvocationExpressionSyntax invocation)
    {
        if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
        {
            var text = memberAccess.ToString();
            return text.StartsWith("Request.Form") ||
                   text.StartsWith("Request.QueryString") ||
                   text.StartsWith("Request.Params");
        }

        return false;
    }
    

    static NivelRisco DetermineXSSRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isCSRFRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineCSRFRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isOpenRedirectRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineOpenRedirectAtack(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isHTTPSEnforcementRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineHTTPSEnforcement(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isCORSRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineCORSRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isEncryptionRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineEncryptionRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isSSRFRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineSSRFRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isTLSRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineTLSRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    private static bool isDoSRelated(SyntaxNode node)
    {
        return true;
    }
    private static NivelRisco DetermineDoSRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

}