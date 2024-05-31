using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Windows.UI.Xaml.Shapes;

public class Vulnerability
{
    public string Tipo { get; set; }
    public string Codigo { get; set; }
    public NivelRisco Risco { get; set; }
    public HashSet<int> Linhas { get; set; }

    public Vulnerability(string type, string node, NivelRisco riskLevel, HashSet<int> lineNumbers)
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
    static char[] mudanca = new char[] { ';', '\n', '\r' };

    public static List<Vulnerability> AnalisarVulnerabilidades(SyntaxTree tree)
    {
        vulnerabilities = new List<Vulnerability>();

        SyntaxNode root = tree.GetRoot();

        var compilation = CSharpCompilation.Create("MyCompilation")
                                            .AddReferences(MetadataReference.CreateFromFile(typeof(object).Assembly.Location))
                                            .AddSyntaxTrees(tree);
        
        var semanticModel = compilation.GetSemanticModel(tree);

        // Analisar vulnerabilidades de XSS
        AnalyzeForSQLInjection(root);

        // Analisar vulnerabilidades de SQL Injection
        //var sqlVulnerabilities = AnalyzeSQLInjection(root);
        //vulnerabilities.AddRange(sqlVulnerabilities);

        return vulnerabilities;
    }

    static SyntaxNode GetScope(SyntaxNode node)
    {
        // Obter o escopo em que o nó está (método, lambda, etc.)
        while (node != null && !(node is MethodDeclarationSyntax || node is LocalFunctionStatementSyntax || node is LambdaExpressionSyntax))
        {
            node = node.Parent;
        }
        return node;
    }

    static void AdicionarVulnerabilidade(string tipo, string codigo, NivelRisco risco, int linha)
    {
        object obj = new object();

        var index = vulnerabilities.IndexOf(
            vulnerabilities.FirstOrDefault(v => v.Codigo == codigo && v.Tipo == tipo));
                       

        lock (obj)
        {
            if (index > -1)
            {
                // Adicionar a nova linha à lista de linhas da vulnerabilidade existente

                vulnerabilities[index].Linhas.Add(linha);

            }
            
            else
            {
                // Adicionar nova vulnerabilidade
                var lineNumbers = new HashSet<int> { linha };
                vulnerabilities.Add(new Vulnerability(tipo, codigo, risco, lineNumbers));
            }
        }
    }

    public static void AnalyzeForSQLInjection(SyntaxNode root)
    {
        var tipo = "SQL Injection";
        var risco = NivelRisco.Alto; // Ajuste conforme necessário

        // Encontrar variáveis inicializadas com strings concatenadas
        var variaveis = root.DescendantNodes().OfType<VariableDeclaratorSyntax>()
                        .Where(v => v.Initializer != null &&
                                    (v.Initializer.Value is BinaryExpressionSyntax binaryExpression && binaryExpression.IsKind(SyntaxKind.AddExpression)));

        // Encontrar todas as instâncias de SqlCommand
        var sqlCommands = root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>()
                          .Where(o => o.Type.ToString().Contains("SqlCommand"));

        foreach (var command in sqlCommands)
        {
            bool isVulnerable = false;

            foreach (var arg in command.ArgumentList.Arguments)
            {
                if (arg.Expression is BinaryExpressionSyntax binaryExpression && binaryExpression.IsKind(SyntaxKind.AddExpression))
                {
                    isVulnerable = true;
                }
                else if (arg.Expression is IdentifierNameSyntax identifier)
                {
                    var variable = variaveis.FirstOrDefault(v => v.Identifier.Text == identifier.Identifier.Text);
                    if (variable != null)
                    {
                        var scope = GetScope(command);
                        if (scope != null && scope.Contains(variable))
                        {
                            isVulnerable = true;
                        }
                    }
                }
            }

            if (isVulnerable)
            {
                string codigo;
                int index = command.Parent.ToString().IndexOfAny(mudanca);

                try
                {
                    codigo = command.Parent.ToString().Substring(0, index);
                }
                catch (Exception ex)
                {
                    codigo = command.Parent.ToString();
                }

                var linha = command.Parent.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

                AdicionarVulnerabilidade(tipo, codigo, risco, linha);

            }
        }
    }
    
    static void AnalyzeForXSS(SyntaxNode root)
    {
        var tipo = "XSS";
        var risco = NivelRisco.Alto; // Ajuste conforme necessário

        // Encontrar variáveis inicializadas com Request.QueryString
        var variaveis = root.DescendantNodes().OfType<VariableDeclaratorSyntax>()
                        .Where(v => v.Initializer != null &&
                                    v.Initializer.Value.ToString().Contains("Request.QueryString"));

        // Verificar se existe pelo menos uma variável encontrada
        if (!variaveis.Any())
        {
            return;
        }

        // Encontrar todas as chamadas para HttpUtility.HtmlEncode
        var codificacoes = root.DescendantNodes().OfType<InvocationExpressionSyntax>()
                           .Where(i => i.Expression.ToString().Contains("HttpUtility.HtmlEncode"));

        if (!codificacoes.Any())
        {
            foreach (var v in variaveis)
            {
                string codigo;
                int index = v.Parent.ToString().IndexOfAny(mudanca);

                try
                {
                    codigo = v.Parent.ToString().Substring(0, index);
                }
                catch (Exception ex)
                {
                    codigo = v.Parent.ToString();
                }

                var linha = v.Parent.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

                AdicionarVulnerabilidade(tipo, codigo, risco, linha);
            }
        }
        else
        {
            // Verificar se cada HttpUtility.HtmlEncode tem como parâmetro de entrada as variáveis encontradas
            foreach (var v in variaveis)
            {
                bool isEncoded = false;

                foreach (var codificacao in codificacoes)
                {
                    var scope = GetScope(codificacao);
                    if (scope != null && scope.Contains(v))
                    {
                        isEncoded = codificacao.ArgumentList.Arguments
                                    .Any(arg => arg.ToString().Contains(v.Identifier.Text));

                        if (!isEncoded)
                        {
                            string codigo;
                            int index = v.Parent.ToString().IndexOfAny(mudanca);

                            try
                            {
                                codigo = v.Parent.ToString().Substring(0, index);
                            }
                            catch (Exception ex)
                            {
                                codigo = v.Parent.ToString();
                            }

                            var linha = v.Parent.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

                            AdicionarVulnerabilidade(tipo, codigo, risco, linha);
                        }
                    }
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
                string codigo;
                int index = m.ToString().IndexOfAny(mudanca);

                try
                {
                    codigo = m.ToString().Substring(0, index);
                }

                catch (ArgumentOutOfRangeException)
                {
                    codigo = m.ToString();
                }

                var linha = m.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

                AdicionarVulnerabilidade(tipo, codigo, risco, linha);
            }
        }


    }
    static void AnalyzeForInsecureDeserialization(SyntaxNode root) 
    {
        var tipo = "Deserialização Insegura";
        var risco = NivelRisco.Alto;

        IEnumerable<VariableDeclaratorSyntax> variaveis;
        IEnumerable<InvocationExpressionSyntax> incovations;
        
        variaveis = root.DescendantNodes().OfType<VariableDeclaratorSyntax>()
        .Where(i => i.Initializer.ToString().Contains("BinaryFormatter"));

        foreach (var v in variaveis)
        {
            incovations = root.DescendantNodes().OfType<InvocationExpressionSyntax>()
                .Where(i => i.Expression.ToString().Contains(v.Identifier + ".Deserialize"));

            foreach (var i in incovations)
            {
                int linha = i.Parent.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                int index = i.Parent.ToString().IndexOfAny(mudanca);

                string codigo;

                try
                {
                    codigo = i.Parent.ToString().Substring(0, index);
                }

                catch (ArgumentOutOfRangeException)
                {
                    codigo = i.Parent.ToString();
                }

                AdicionarVulnerabilidade(tipo, codigo, risco, linha);
            }
       
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