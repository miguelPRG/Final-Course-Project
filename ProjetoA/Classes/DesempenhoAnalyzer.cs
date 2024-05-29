using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using Windows.Foundation.Metadata;

public class DesempenhoAnalyzer
{
    delegate void AnaliseDesempenho(SyntaxNode root, Dictionary<string, int[]> findings);

    public async Task<StringBuilder> AnalyzeCodeAsync(SyntaxNode root, ConcurrentDictionary<int, int> linhasImportantes)
    {
        AnaliseDesempenho[] analisesDesempenho =
        {
            AnalyzeUnnecessaryVariableCreation,
            AnalyzeInefficientDataStructures,
            AnalyzeLackOfInputValidation,
            AnalyzeExcessiveUseOfExceptions,
            AnalyzeInefficientStringConcatenation,
            AnalyzeNotDisposingOfResources,
            //AnalyzeNotUsingAsynchronousProgramming,
        };

        // Create a list to store the findings
        var findings = new Dictionary<string, int[]>();

        // Analyze the code for each pattern
        List<Task> tasks = new List<Task>();

        foreach (var func in analisesDesempenho)
        {
            tasks.Add(Task.Run(() => func(root, findings)));   
        }

        await Task.WhenAll(tasks);

        // Save the findings to an HTML table
        StringBuilder table = new StringBuilder(null);

        if (findings.Count() <= 0)
        {
            return await Task.FromResult(table); 
        }

        table.AppendLine("<table>");
        table.AppendLine("<tr><th>Pattern Name</th><th>Line Numbers</th></tr>");
        table.AppendLine("<tr>");

        foreach (var finding in findings)
        {
            table.Append($"<td>{finding.Key}</td><td>");

            for (int j = 0; j < finding.Value.Count(); j++)
            {
                table.Append($"<a href=\"#linha-numero{finding.Value[j]}\" onclick=selecionar({finding.Value[j]})>{finding.Value[j]}</a>");

                linhasImportantes[finding.Value[j]] = 3;

                if (j + 1 < finding.Value.Count())
                {
                    table.Append(',');
                }
            }

            table.Append("</td></tr>");
        }

        table.AppendLine("</table>");

        return await Task.FromResult(table);
       
    }

    void AnalyzeUnnecessaryVariableCreation(SyntaxNode root, Dictionary<string, int[]> findings)
    {
        var variableDeclarations = root.DescendantNodes().OfType<VariableDeclarationSyntax>();
        foreach (var declaration in variableDeclarations)
        {
            foreach (var variable in declaration.Variables)
            {
                if (IsUnnecessaryVariableCreation(variable, root))
                {
                    findings["Criação Desnecessária de Variaveis"] = findings.TryGetValue("Criação Desnecessária de Variaveis", out var lines)
                        ? lines.Concat(new[] { variable.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
                        : new[] { variable.GetLocation().GetLineSpan().StartLinePosition.Line + 1 };
                }
            }
        }
    }
    void AnalyzeInefficientDataStructures(SyntaxNode root, Dictionary<string, int[]> findings)
    {
        var dataStructureDeclarations = root.DescendantNodes().OfType<VariableDeclarationSyntax>();
        foreach (var declaration in dataStructureDeclarations)
        {
            var type = declaration.Type.ToString();
            if (IsInefficientDataStructure(type))
            {
                var line = declaration.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                if (findings.TryGetValue("Estrutura de Dados Ineficiente", out var lines))
                {
                    findings["Estrutura de Dados Ineficiente"] = lines.Concat(new[] { line }).ToArray();
                }
                else
                {
                    findings["Estrutura de Dados Ineficiente"] = new[] { line };
                }
            }
        }
    }
    void AnalyzeLackOfInputValidation(SyntaxNode root, Dictionary<string, int[]> findings)
    {
        var methodDeclarations = root.DescendantNodes().OfType<MethodDeclarationSyntax>();
        foreach (var method in methodDeclarations)
        {
            if (IsLackOfInputValidation(method))
            {
               findings["Falta de validação de Input"] = findings.TryGetValue("Falta de validação de Input", out var lines)
               ? lines.Concat(new[] { method.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
               : new[] { method.GetLocation().GetLineSpan().StartLinePosition.Line + 1 };
            }
        }
    }
    void AnalyzeExcessiveUseOfExceptions(SyntaxNode root, Dictionary<string, int[]> findings)
    {
        var throwStatements = root.DescendantNodes().OfType<ThrowStatementSyntax>();
        foreach (var statement in throwStatements)
        {
            if (IsExcessiveUseOfExceptions(statement))
            {
               findings["Uso excessivo de exceções"] = findings.TryGetValue("Uso excessivo de exceções", out var lines)
               ? lines.Concat(new[] { statement.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
               : new[] { statement.GetLocation().GetLineSpan().StartLinePosition.Line + 1 };
            }
        }
    }
    void AnalyzeInefficientStringConcatenation(SyntaxNode root, Dictionary<string, int[]> findings)
    {
        var stringConcatenations = root.DescendantNodes().OfType<InterpolatedStringContentSyntax>();
        foreach (var concatenation in stringConcatenations)
        {
            if (IsInefficientStringConcatenation(concatenation))
            {
                findings["Concatenação de string ineficiente"] = findings.TryGetValue("Concatenação de string ineficiente\"", out var lines)
                ? lines.Concat(new[] { concatenation.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
                : new[] { concatenation.GetLocation().GetLineSpan().StartLinePosition.Line + 1 };
            }
        }
    }
    void AnalyzeNotDisposingOfResources(SyntaxNode root, Dictionary<string, int[]> findings)
    {
        var usingStatements = root.DescendantNodes().OfType<UsingStatementSyntax>();
        foreach (var statement in usingStatements)
        {
            if (IsNotDisposingOfResources(statement))
            {
              findings["Não disposição de recursos"] = findings.TryGetValue("Não disposição de recursos", out var lines)
              ? lines.Concat(new[] { statement.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
              : new[] { statement.GetLocation().GetLineSpan().StartLinePosition.Line + 1 };
            }
        }
    }
    /*void AnalyzeNotUsingAsynchronousProgramming(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var methodDeclarations = syntaxTree.GetRoot().DescendantNodes().OfType<MethodDeclarationSyntax>();
        foreach (var method in methodDeclarations)
        {
            if (IsNotUsingAsynchronousProgramming(method))
            {
              findings["Não utlização de programação assíncrona"] = findings.TryGetValue("Não utlização de programação assíncrona", out var lines)
              ? lines.Concat(new[] { method.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
              : new[] { method.GetLocation().GetLineSpan().StartLinePosition.Line + 1 };
            }
        }
    }*/

    bool IsUnnecessaryVariableCreation(VariableDeclaratorSyntax variable, SyntaxNode root)
    {
        var initializer = variable.Initializer;
        if (initializer == null)
            return false;

        var variableName = variable.Identifier.ValueText;

        // Verifica se a variável é usada apenas uma vez como uma declaração de expressão independente
        var usages = root.DescendantNodes().OfType<IdentifierNameSyntax>()
            .Where(id => id.Identifier.ValueText == variableName);
        var standaloneUsages = usages.Where(id => id.Parent is ExpressionStatementSyntax || id.Parent is ArgumentSyntax);

        return standaloneUsages.Count() <=2;
    }
    bool IsInefficientDataStructure(string typeName)
    {

        int genericStartIndex = typeName.IndexOf('<');
        if (genericStartIndex != -1)
        {
            typeName = typeName.Substring(0, genericStartIndex);
        }

        switch (typeName)
        {
            case "ArrayList":
            case "Hashtable":
            case "Queue":
            case "Stack":
            case "ConcurrentDictionary":
                // These are considered inefficient data structures
                return true;
            default:
                // Other types are not considered inefficient
                return false;
        }
    }
    bool IsLackOfInputValidation(MethodDeclarationSyntax method)
    {
        // Verificar se o método tem parâmetros
        if (method.ParameterList.Parameters.Count == 0)
        {
            return false; // Se não tiver parâmetros, não há input para validar
        }

        // Verificar se há alguma lógica de validação de entrada no corpo do método
        var methodBody = method.Body;
        if (methodBody == null)
        {
            return true; // Se o método não tiver corpo, assume-se que não há validação de entrada
        }

        // Verificar se há chamadas a métodos de validação de entrada
        var validationMethods = new[] { "string.IsNullOrEmpty", "int.TryParse", "long.TryParse", "bool.TryParse", "double.TryParse", "DateTime.TryParse" };
        var validationCalls = methodBody.DescendantNodes().OfType<InvocationExpressionSyntax>()
            .Select(invocation => invocation.Expression.ToString())
            .Any(expression => validationMethods.Any(m => expression.Contains(m)));

        if (validationCalls)
        {
            return false; // Se há chamadas a métodos de validação de entrada, assume-se que há validação de entrada
        }

        // Verificar se há verificações de condição de validação de entrada
        var conditionals = methodBody.DescendantNodes().OfType<BinaryExpressionSyntax>()
            .Where(binaryExpression => binaryExpression.IsKind(SyntaxKind.EqualsExpression) || binaryExpression.IsKind(SyntaxKind.NotEqualsExpression))
            .Select(binaryExpression => (binaryExpression.Left, binaryExpression.Right))
            .Any(pair => pair.Left is IdentifierNameSyntax identifier &&
                         method.ParameterList.Parameters.Any(parameter => parameter.Identifier.Text == identifier.Identifier.Text) &&
                         pair.Right.IsKind(SyntaxKind.NullLiteralExpression));

        if (conditionals)
        {
            return false; // Se há uma verificação de condição que checa se o input é nulo, assume-se que há validação de entrada
        }

        var fileOperations = methodBody.DescendantNodes().OfType<InvocationExpressionSyntax>()
        .Where(invocation => invocation.Expression is MemberAccessExpressionSyntax memberAccess &&
                          (memberAccess.Name.ToString().Equals("ReadAllText") || memberAccess.Name.ToString().Equals("WriteAllText")
                          || memberAccess.Name.ToString().Equals("IsNullOrEmpty")));


        if (fileOperations.Any())
        {
            return false; // Se houver operações de leitura/escrita de arquivos sem validação de entrada, retorna falso
        }

        // Se não há nenhuma lógica de validação de entrada, retorna true
        return true;
    }
    bool IsExcessiveUseOfExceptions(ThrowStatementSyntax statement)
    {
        var parent = statement.Parent;
        while (parent != null)
        {
            if (parent is TryStatementSyntax tryStatement)
            {
                // Verifica se há apenas um bloco catch
                if (tryStatement.Catches.Count > 1)
                {
                    return true;
                }

                // Verifica se o bloco try está vazio
                if (tryStatement.Block.Statements.Count == 0)
                {
                    return true;
                }

                break;
            }
            parent = parent.Parent;
        }
        return false;
    }
    bool IsInefficientStringConcatenation(InterpolatedStringContentSyntax concatenation)
    {
        // Verificar se a concatenação ocorre dentro de um loop
        var parent = concatenation.Parent;
        while (parent != null)
        {
            if (parent is ForStatementSyntax || parent is WhileStatementSyntax || parent is DoStatementSyntax || parent is ForEachStatementSyntax)
            {
                return true;
            }
            parent = parent.Parent;
        }

        // Verificar se a concatenação envolve muitas operações de concatenação
        var expressions = concatenation.DescendantNodes().OfType<BinaryExpressionSyntax>();
        var concatenationCount = 0;
        foreach (var expression in expressions)
        {
            if (expression.OperatorToken.IsKind(SyntaxKind.PlusToken))
            {
                concatenationCount++;
            }
        }

        if (concatenationCount > 3) // ajuste o valor de acordo com a sua necessidade
        {
            return true;
        }

        // Verificar se a concatenação envolve uma string literal longa
        var literals = concatenation.DescendantNodes().OfType<LiteralExpressionSyntax>();
        foreach (var literal in literals)
        {
            if (literal.IsKind(SyntaxKind.StringLiteralExpression) && literal.Token.ValueText.Length > 50) // ajuste o comprimento conforme necessário
            {
                return true;
            }
        }

        return false;
    }
    bool IsNotDisposingOfResources(UsingStatementSyntax statement)
    {
        // Verifica se há declarações de variáveis dentro do bloco using
        var declaration = statement.Declaration;
        if (declaration != null)
        {
            foreach (var variable in declaration.Variables)
            {
                // Verifica se a variável não está sendo inicializada com null
                if (!variable.Initializer.Value.IsKind(SyntaxKind.NullLiteralExpression))
                {
                    return true; // Recurso não está sendo descartado corretamente
                }
            }
        }

        // Verifica se há expressões de recurso no bloco using
        var expression = statement.Expression;
        if (expression != null)
        {
            // Verifica se a expressão não é nula
            if (!expression.IsKind(SyntaxKind.NullLiteralExpression))
            {
                return true; // Recurso não está sendo descartado corretamente
            }

            // Verifica se a expressão é uma chamada de método
            if (expression is InvocationExpressionSyntax invocation)
            {
                // Verifica se o método chamado é um método de abertura de arquivo, como File.Open()
                var methodName = invocation.Expression.ToString();
                if (methodName.Equals("File.Open"))
                {
                    return true; // Recurso não está sendo descartado corretamente
                }
            }
        }

        return false; // Não foram encontrados problemas de falta de disposição de recursos
    }
   /* bool IsNotUsingAsynchronousProgramming(MethodDeclarationSyntax method)
    {
        var methodBody = method.Body;
        if (methodBody == null)
        {
            // Se o método não tem corpo, não pode usar programação assíncrona
            return false;
        }

        // Verifica se há chamadas assíncronas dentro do corpo do método
        var asyncCalls = methodBody.DescendantNodes().OfType<InvocationExpressionSyntax>()
            .Any(invocation => invocation.Expression is IdentifierNameSyntax identifier &&
                                identifier.Identifier.Text.EndsWith("Async"));

        return !asyncCalls;
    }*/
}